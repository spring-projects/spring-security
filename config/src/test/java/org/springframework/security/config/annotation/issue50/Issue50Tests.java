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

package org.springframework.security.config.annotation.issue50;

import jakarta.transaction.Transactional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.issue50.domain.User;
import org.springframework.security.config.annotation.issue50.repo.UserRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Rob Winch
 *
 */
@Transactional
@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = { ApplicationConfig.class, SecurityConfig.class })
public class Issue50Tests {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private UserRepository userRepo;

	@BeforeEach
	public void setup() {
		SecurityContextHolder.getContext()
				.setAuthentication(new TestingAuthenticationToken("test", null, "ROLE_ADMIN"));
	}

	@AfterEach
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	// https://github.com/spring-projects/spring-security-javaconfig/issues/50
	public void loadWhenGlobalMethodSecurityConfigurationThenAuthenticationManagerLazy() {
		// no exception
	}

	@Test
	public void authenticateWhenMissingUserThenUsernameNotFoundException() {
		assertThatExceptionOfType(UsernameNotFoundException.class).isThrownBy(() -> this.authenticationManager
				.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("test", "password")));
	}

	@Test
	public void authenticateWhenInvalidPasswordThenBadCredentialsException() {
		this.userRepo.save(User.withUsernameAndPassword("test", "password"));
		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> this.authenticationManager
				.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("test", "invalid")));
	}

	@Test
	public void authenticateWhenValidUserThenAuthenticates() {
		this.userRepo.save(User.withUsernameAndPassword("test", "password"));
		Authentication result = this.authenticationManager
				.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("test", "password"));
		assertThat(result.getName()).isEqualTo("test");
	}

	@Test
	public void globalMethodSecurityIsEnabledWhenNotAllowedThenAccessDenied() {
		SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("test", null, "ROLE_USER"));
		this.userRepo.save(User.withUsernameAndPassword("denied", "password"));
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> this.authenticationManager
				.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("test", "password")));
	}

}
