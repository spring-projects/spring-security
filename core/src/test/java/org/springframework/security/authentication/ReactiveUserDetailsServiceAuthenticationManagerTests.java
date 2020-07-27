/*
 * Copyright 2002-2017 the original author or authors.
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
import reactor.test.StepVerifier;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class ReactiveUserDetailsServiceAuthenticationManagerTests {

	@Mock
	ReactiveUserDetailsService repository;

	@Mock
	PasswordEncoder passwordEncoder;

	UserDetailsRepositoryReactiveAuthenticationManager manager;

	String username;

	String password;

	@Before
	public void setup() {
		this.manager = new UserDetailsRepositoryReactiveAuthenticationManager(this.repository);
		this.username = "user";
		this.password = "pass";
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullUserDetailsService() {
		ReactiveUserDetailsService userDetailsService = null;
		new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsService);
	}

	@Test
	public void authenticateWhenUserNotFoundThenBadCredentials() {
		given(this.repository.findByUsername(this.username)).willReturn(Mono.empty());

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(this.username,
				this.password);
		Mono<Authentication> authentication = this.manager.authenticate(token);

		StepVerifier.create(authentication).expectError(BadCredentialsException.class).verify();
	}

	@Test
	public void authenticateWhenPasswordNotEqualThenBadCredentials() {
		// @formatter:off
		UserDetails user = PasswordEncodedUser.withUsername(this.username)
			.password(this.password)
			.roles("USER")
			.build();
		// @formatter:on
		given(this.repository.findByUsername(user.getUsername())).willReturn(Mono.just(user));

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(this.username,
				this.password + "INVALID");
		Mono<Authentication> authentication = this.manager.authenticate(token);

		StepVerifier.create(authentication).expectError(BadCredentialsException.class).verify();
	}

	@Test
	public void authenticateWhenSuccessThenSuccess() {
		// @formatter:off
		UserDetails user = PasswordEncodedUser.withUsername(this.username)
			.password(this.password)
			.roles("USER")
			.build();
		// @formatter:on
		given(this.repository.findByUsername(user.getUsername())).willReturn(Mono.just(user));

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(this.username,
				this.password);
		Authentication authentication = this.manager.authenticate(token).block();

		assertThat(authentication).isEqualTo(authentication);
	}

	@Test
	public void authenticateWhenPasswordEncoderAndSuccessThenSuccess() {
		this.manager.setPasswordEncoder(this.passwordEncoder);
		given(this.passwordEncoder.matches(any(), any())).willReturn(true);
		User user = new User(this.username, this.password, AuthorityUtils.createAuthorityList("ROLE_USER"));
		given(this.repository.findByUsername(user.getUsername())).willReturn(Mono.just(user));

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(this.username,
				this.password);
		Authentication authentication = this.manager.authenticate(token).block();

		assertThat(authentication).isEqualTo(authentication);
	}

	@Test
	public void authenticateWhenPasswordEncoderAndFailThenFail() {
		this.manager.setPasswordEncoder(this.passwordEncoder);
		given(this.passwordEncoder.matches(any(), any())).willReturn(false);
		User user = new User(this.username, this.password, AuthorityUtils.createAuthorityList("ROLE_USER"));
		given(this.repository.findByUsername(user.getUsername())).willReturn(Mono.just(user));

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(this.username,
				this.password);

		Mono<Authentication> authentication = this.manager.authenticate(token);

		StepVerifier.create(authentication).expectError(BadCredentialsException.class).verify();
	}

}
