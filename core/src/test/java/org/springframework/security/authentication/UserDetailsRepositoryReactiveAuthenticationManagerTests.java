/*
 * Copyright 2002-2019 the original author or authors.
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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.ReactiveUserDetailsPasswordService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;

/**
 * @author Rob Winch
 * @author Eddú Meléndez
 * @since 5.1
 */
@RunWith(MockitoJUnitRunner.class)
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

	@Before
	public void setup() {
		this.manager = new UserDetailsRepositoryReactiveAuthenticationManager(this.userDetailsService);
		given(this.scheduler.schedule(any())).willAnswer(a -> {
			Runnable r = a.getArgument(0);
			return Schedulers.immediate().schedule(r);
		});
	}

	@Test
	public void setSchedulerWhenNullThenIllegalArgumentException() {
		assertThatCode(() -> this.manager.setScheduler(null)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void authentiateWhenCustomSchedulerThenUsed() {
		given(this.userDetailsService.findByUsername(any())).willReturn(Mono.just(this.user));
		given(this.encoder.matches(any(), any())).willReturn(true);
		this.manager.setScheduler(this.scheduler);
		this.manager.setPasswordEncoder(this.encoder);
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(this.user,
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
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(this.user,
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
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(this.user,
				this.user.getPassword());

		assertThatThrownBy(() -> this.manager.authenticate(token).block()).isInstanceOf(BadCredentialsException.class);

		verifyZeroInteractions(this.userDetailsPasswordService);
	}

	@Test
	public void authenticateWhenPasswordServiceAndUpgradeFalseThenNotUpdated() {
		given(this.userDetailsService.findByUsername(any())).willReturn(Mono.just(this.user));
		given(this.encoder.matches(any(), any())).willReturn(true);
		given(this.encoder.upgradeEncoding(any())).willReturn(false);
		this.manager.setPasswordEncoder(this.encoder);
		this.manager.setUserDetailsPasswordService(this.userDetailsPasswordService);
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(this.user,
				this.user.getPassword());

		Authentication result = this.manager.authenticate(token).block();

		verifyZeroInteractions(this.userDetailsPasswordService);
	}

	@Test
	public void authenticateWhenPostAuthenticationChecksFail() {
		given(this.userDetailsService.findByUsername(any())).willReturn(Mono.just(this.user));
		willThrow(new LockedException("account is locked")).given(this.postAuthenticationChecks).check(any());
		given(this.encoder.matches(any(), any())).willReturn(true);
		this.manager.setPasswordEncoder(this.encoder);
		this.manager.setPostAuthenticationChecks(this.postAuthenticationChecks);

		assertThatExceptionOfType(LockedException.class).isThrownBy(() -> this.manager
				.authenticate(new UsernamePasswordAuthenticationToken(this.user, this.user.getPassword())).block())
				.withMessage("account is locked");

		verify(this.postAuthenticationChecks).check(eq(this.user));
	}

	@Test
	public void authenticateWhenPostAuthenticationChecksNotSet() {
		given(this.userDetailsService.findByUsername(any())).willReturn(Mono.just(this.user));
		given(this.encoder.matches(any(), any())).willReturn(true);
		this.manager.setPasswordEncoder(this.encoder);

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(this.user,
				this.user.getPassword());

		this.manager.authenticate(token).block();

		verifyZeroInteractions(this.postAuthenticationChecks);
	}

	@Test(expected = AccountExpiredException.class)
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

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(expiredUser,
				expiredUser.getPassword());

		this.manager.authenticate(token).block();
	}

	@Test(expected = LockedException.class)
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

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(lockedUser,
				lockedUser.getPassword());

		this.manager.authenticate(token).block();
	}

	@Test(expected = DisabledException.class)
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

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(disabledUser,
				disabledUser.getPassword());

		this.manager.authenticate(token).block();
	}

}
