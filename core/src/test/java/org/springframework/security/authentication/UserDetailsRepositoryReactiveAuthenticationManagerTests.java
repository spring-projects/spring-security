/*
 * Copyright 2002-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.authentication;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import org.springframework.context.MessageSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.ReactiveUserDetailsPasswordService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * @author Rob Winch
 * @author Eddú Meléndez
 * @since 5.1
 */
@ExtendWith(MockitoExtension.class)
public class UserDetailsRepositoryReactiveAuthenticationManagerTests {

	@Mock
	private ReactiveUserDetailsService userDetailsService;

	@Mock
	private PasswordEncoder encoder;

	@Mock
	private ReactiveUserDetailsPasswordService userDetailsPasswordService;

	@Mock
	private Scheduler scheduler;

	@Mock
	private UserDetailsChecker postAuthenticationChecks;

	// @formatter:off
	private UserDetails user = User.withUsername("user")
		.password("password")
		.roles("USER")
		.build();
	// @formatter:on
	private UserDetailsRepositoryReactiveAuthenticationManager manager;

	@BeforeEach
	public void setup() {
		this.manager = new UserDetailsRepositoryReactiveAuthenticationManager(this.userDetailsService);
	}

	@Test
	public void setSchedulerWhenNullThenIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> this.manager.setScheduler(null));
	}

	@Test
	public void authenticateWhenCustomSchedulerThenUsed() {
		given(this.scheduler.schedule(any())).willAnswer((a) -> {
			Runnable r = a.getArgument(0);
			return Schedulers.immediate().schedule(r);
		});
		given(this.userDetailsService.findByUsername(any())).willReturn(Mono.just(this.user));
		given(this.encoder.matches(any(), any())).willReturn(true);
		this.manager.setScheduler(this.scheduler);
		this.manager.setPasswordEncoder(this.encoder);
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated(this.user,
				this.user.getPassword());
		Authentication result = this.manager.authenticate(token).block();
		verify(this.scheduler).schedule(any());
	}

	@Test
	public void authenticateWhenPasswordServiceThenUpdated() {
		String encodedPassword = "encoded";
		given(this.userDetailsService.findByUsername(any())).willReturn(Mono.just(this.user));
		given(this.encoder.matches(any(), any())).willReturn(true);
		given(this.encoder.upgradeEncoding(any())).willReturn(true);
		given(this.encoder.encode(any())).willReturn(encodedPassword);
		given(this.userDetailsPasswordService.updatePassword(any(), any())).willReturn(Mono.just(this.user));
		this.manager.setPasswordEncoder(this.encoder);
		this.manager.setUserDetailsPasswordService(this.userDetailsPasswordService);
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated(this.user,
				this.user.getPassword());
		Authentication result = this.manager.authenticate(token).block();
		verify(this.encoder).encode(this.user.getPassword());
		verify(this.userDetailsPasswordService).updatePassword(eq(this.user), eq(encodedPassword));
	}

	@Test
	public void authenticateWhenPasswordServiceAndBadCredentialsThenNotUpdated() {
		given(this.userDetailsService.findByUsername(any())).willReturn(Mono.just(this.user));
		given(this.encoder.matches(any(), any())).willReturn(false);
		this.manager.setPasswordEncoder(this.encoder);
		this.manager.setUserDetailsPasswordService(this.userDetailsPasswordService);
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated(this.user,
				this.user.getPassword());
		assertThatExceptionOfType(BadCredentialsException.class)
				.isThrownBy(() -> this.manager.authenticate(token).block());
		verifyNoMoreInteractions(this.userDetailsPasswordService);
	}

	@Test
	public void authenticateWhenPasswordServiceAndUpgradeFalseThenNotUpdated() {
		given(this.userDetailsService.findByUsername(any())).willReturn(Mono.just(this.user));
		given(this.encoder.matches(any(), any())).willReturn(true);
		given(this.encoder.upgradeEncoding(any())).willReturn(false);
		this.manager.setPasswordEncoder(this.encoder);
		this.manager.setUserDetailsPasswordService(this.userDetailsPasswordService);
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated(this.user,
				this.user.getPassword());
		Authentication result = this.manager.authenticate(token).block();
		verifyNoMoreInteractions(this.userDetailsPasswordService);
	}

	@Test
	public void authenticateWhenPostAuthenticationChecksFail() {
		given(this.userDetailsService.findByUsername(any())).willReturn(Mono.just(this.user));
		willThrow(new LockedException("account is locked")).given(this.postAuthenticationChecks).check(any());
		given(this.encoder.matches(any(), any())).willReturn(true);
		this.manager.setPasswordEncoder(this.encoder);
		this.manager.setPostAuthenticationChecks(this.postAuthenticationChecks);
		assertThatExceptionOfType(LockedException.class).isThrownBy(() -> this.manager
				.authenticate(UsernamePasswordAuthenticationToken.unauthenticated(this.user, this.user.getPassword()))
				.block()).withMessage("account is locked");
		verify(this.postAuthenticationChecks).check(eq(this.user));
	}

	@Test
	public void authenticateWhenPostAuthenticationChecksNotSet() {
		given(this.userDetailsService.findByUsername(any())).willReturn(Mono.just(this.user));
		given(this.encoder.matches(any(), any())).willReturn(true);
		this.manager.setPasswordEncoder(this.encoder);
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated(this.user,
				this.user.getPassword());
		this.manager.authenticate(token).block();
		verifyNoMoreInteractions(this.postAuthenticationChecks);
	}

	@Test
	public void authenticateWhenAccountExpiredThenException() {
		this.manager.setPasswordEncoder(this.encoder);
		// @formatter:off
		UserDetails expiredUser = User.withUsername("user")
				.password("password")
				.roles("USER")
				.accountExpired(true)
				.build();
		// @formatter:on
		given(this.userDetailsService.findByUsername(any())).willReturn(Mono.just(expiredUser));
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated(expiredUser,
				expiredUser.getPassword());
		assertThatExceptionOfType(AccountExpiredException.class)
				.isThrownBy(() -> this.manager.authenticate(token).block());
	}

	@Test
	public void authenticateWhenAccountLockedThenException() {
		this.manager.setPasswordEncoder(this.encoder);
		// @formatter:off
		UserDetails lockedUser = User.withUsername("user")
				.password("password")
				.roles("USER")
				.accountLocked(true)
				.build();
		// @formatter:on
		given(this.userDetailsService.findByUsername(any())).willReturn(Mono.just(lockedUser));
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated(lockedUser,
				lockedUser.getPassword());
		assertThatExceptionOfType(LockedException.class).isThrownBy(() -> this.manager.authenticate(token).block());
	}

	@Test
	public void authenticateWhenAccountDisabledThenException() {
		this.manager.setPasswordEncoder(this.encoder);
		// @formatter:off
		UserDetails disabledUser = User.withUsername("user")
				.password("password")
				.roles("USER")
				.disabled(true)
				.build();
		// @formatter:on
		given(this.userDetailsService.findByUsername(any())).willReturn(Mono.just(disabledUser));
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated(disabledUser,
				disabledUser.getPassword());
		assertThatExceptionOfType(DisabledException.class).isThrownBy(() -> this.manager.authenticate(token).block());
	}

	@Test
	public void setMessageSourceWhenNullThenThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.manager.setMessageSource(null));
	}

	@Test
	public void setMessageSourceWhenNotNullThenCanGet() {
		MessageSource source = mock(MessageSource.class);
		this.manager.setMessageSource(source);
		String code = "code";
		this.manager.messages.getMessage(code);
		verify(source).getMessage(eq(code), any(), any());
	}

}
