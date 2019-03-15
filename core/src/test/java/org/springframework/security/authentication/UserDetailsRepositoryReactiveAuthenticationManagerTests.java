/*
 * Copyright 2002-2018 the original author or authors.
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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.ReactiveUserDetailsPasswordService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

/**
 * @author Rob Winch
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

	private UserDetails user = User.withUsername("user")
		.password("password")
		.roles("USER")
		.build();

	private UserDetailsRepositoryReactiveAuthenticationManager manager;

	@Before
	public void setup() {
		this.manager = new UserDetailsRepositoryReactiveAuthenticationManager(this.userDetailsService);
		when(this.scheduler.schedule(any())).thenAnswer(a -> {
			Runnable r = a.getArgument(0);
			return Schedulers.immediate().schedule(r);
		});
	}

	@Test
	public void setSchedulerWhenNullThenIllegalArgumentException() {
		assertThatCode(() -> this.manager.setScheduler(null))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void authentiateWhenCustomSchedulerThenUsed() {
		when(this.userDetailsService.findByUsername(any())).thenReturn(Mono.just(this.user));
		when(this.encoder.matches(any(), any())).thenReturn(true);
		this.manager.setScheduler(this.scheduler);
		this.manager.setPasswordEncoder(this.encoder);
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
				this.user, this.user.getPassword());

		Authentication result = this.manager.authenticate(token).block();

		verify(this.scheduler).schedule(any());
	}

	@Test
	public void authenticateWhenPasswordServiceThenUpdated() {
		String encodedPassword = "encoded";
		when(this.userDetailsService.findByUsername(any())).thenReturn(Mono.just(this.user));
		when(this.encoder.matches(any(), any())).thenReturn(true);
		when(this.encoder.upgradeEncoding(any())).thenReturn(true);
		when(this.encoder.encode(any())).thenReturn(encodedPassword);
		when(this.userDetailsPasswordService.updatePassword(any(), any())).thenReturn(Mono.just(this.user));
		this.manager.setPasswordEncoder(this.encoder);
		this.manager.setUserDetailsPasswordService(this.userDetailsPasswordService);
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
				this.user, this.user.getPassword());

		Authentication result = this.manager.authenticate(token).block();

		verify(this.encoder).encode(this.user.getPassword());
		verify(this.userDetailsPasswordService).updatePassword(eq(this.user), eq(encodedPassword));
	}

	@Test
	public void authenticateWhenPasswordServiceAndBadCredentialsThenNotUpdated() {
		when(this.userDetailsService.findByUsername(any())).thenReturn(Mono.just(this.user));
		when(this.encoder.matches(any(), any())).thenReturn(false);
		this.manager.setPasswordEncoder(this.encoder);
		this.manager.setUserDetailsPasswordService(this.userDetailsPasswordService);
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
				this.user, this.user.getPassword());

		assertThatThrownBy(() -> this.manager.authenticate(token).block())
			.isInstanceOf(BadCredentialsException.class);

		verifyZeroInteractions(this.userDetailsPasswordService);
	}

	@Test
	public void authenticateWhenPasswordServiceAndUpgradeFalseThenNotUpdated() {
		when(this.userDetailsService.findByUsername(any())).thenReturn(Mono.just(this.user));
		when(this.encoder.matches(any(), any())).thenReturn(true);
		when(this.encoder.upgradeEncoding(any())).thenReturn(false);
		this.manager.setPasswordEncoder(this.encoder);
		this.manager.setUserDetailsPasswordService(this.userDetailsPasswordService);
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
				this.user, this.user.getPassword());

		Authentication result = this.manager.authenticate(token).block();

		verifyZeroInteractions(this.userDetailsPasswordService);
	}
}
