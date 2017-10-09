/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;

import org.springframework.security.core.userdetails.UserDetailsRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class UserDetailsRepositoryAuthenticationManagerTests {
	@Mock
	UserDetailsRepository repository;
	@Mock
	PasswordEncoder passwordEncoder;
	UserDetailsRepositoryAuthenticationManager manager;
	String username;
	String password;

	@Before
	public void setup() {
		manager = new UserDetailsRepositoryAuthenticationManager(repository);
		username = "user";
		password = "pass";
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullUserDetailsRepository() {
		UserDetailsRepository udr = null;
		new UserDetailsRepositoryAuthenticationManager(udr);
	}

	@Test
	public void authenticateWhenUserNotFoundThenBadCredentials() {
		when(repository.findByUsername(username)).thenReturn(Mono.empty());

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
		Mono<Authentication> authentication = manager.authenticate(token);

		StepVerifier
			.create(authentication)
			.expectError(BadCredentialsException.class)
			.verify();
	}

	@Test
	public void authenticateWhenPasswordNotEqualThenBadCredentials() {
		User user = new User(username, password, AuthorityUtils.createAuthorityList("ROLE_USER"));
		when(repository.findByUsername(user.getUsername())).thenReturn(Mono.just(user));

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password + "INVALID");
		Mono<Authentication> authentication = manager.authenticate(token);

		StepVerifier
			.create(authentication)
			.expectError(BadCredentialsException.class)
			.verify();
	}

	@Test
	public void authenticateWhenSuccessThenSuccess() {
		User user = new User(username, password, AuthorityUtils.createAuthorityList("ROLE_USER"));
		when(repository.findByUsername(user.getUsername())).thenReturn(Mono.just(user));

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
		Authentication authentication = manager.authenticate(token).block();

		assertThat(authentication).isEqualTo(authentication);
	}

	@Test
	public void authenticateWhenPasswordEncoderAndSuccessThenSuccess() {
		this.manager.setPasswordEncoder(this.passwordEncoder);
		when(this.passwordEncoder.matches(any(), any())).thenReturn(true);
		User user = new User(this.username, this.password, AuthorityUtils.createAuthorityList("ROLE_USER"));
		when(this.repository.findByUsername(user.getUsername())).thenReturn(Mono.just(user));

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
			this.username, this.password);
		Authentication authentication = this.manager.authenticate(token).block();

		assertThat(authentication).isEqualTo(authentication);
	}

	@Test
	public void authenticateWhenPasswordEncoderAndFailThenFail() {
		this.manager.setPasswordEncoder(this.passwordEncoder);
		when(this.passwordEncoder.matches(any(), any())).thenReturn(false);
		User user = new User(this.username, this.password, AuthorityUtils.createAuthorityList("ROLE_USER"));
		when(this.repository.findByUsername(user.getUsername())).thenReturn(Mono.just(user));

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
			this.username, this.password);

		Mono<Authentication> authentication = this.manager.authenticate(token);

		StepVerifier
			.create(authentication)
			.expectError(BadCredentialsException.class)
			.verify();
	}
}
