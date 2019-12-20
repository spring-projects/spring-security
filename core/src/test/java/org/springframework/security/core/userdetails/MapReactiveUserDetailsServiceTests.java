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
package org.springframework.security.core.userdetails;


import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import org.junit.After;
import org.junit.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolder;

import reactor.core.publisher.Mono;

public class MapReactiveUserDetailsServiceTests {
	private static final String PASSWORD = "password";
	private static final String USERNAME = "user";
	private static final UserDetails USER_DETAILS = User.withUsername(USERNAME)
			.password(PASSWORD)
			.roles("USER")
			.build();

	private final MapReactiveUserDetailsService users = new MapReactiveUserDetailsService(Arrays.asList(USER_DETAILS));

	@After
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullUsers() {
		Collection<UserDetails> users = null;
		new MapReactiveUserDetailsService(users);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorEmptyUsers() {
		Collection<UserDetails> users = Collections.emptyList();
		new MapReactiveUserDetailsService(users);
	}

	@Test
	public void constructorCaseIntensiveKey() {
		UserDetails userDetails = User.withUsername("USER").password(PASSWORD).roles("USER").build();
		MapReactiveUserDetailsService userDetailsService = new MapReactiveUserDetailsService(userDetails);
		assertThat(userDetailsService.findByUsername(USERNAME).block()).isEqualTo(userDetails);
	}

	@Test
	public void findByUsernameWhenFoundThenReturns() {
		assertThat((users.findByUsername(USERNAME).block())).isEqualTo(USER_DETAILS);
	}

	@Test
	public void findByUsernameWhenDifferentCaseThenReturns() {
		assertThat((users.findByUsername("uSeR").block())).isEqualTo(USER_DETAILS);
	}

	@Test
	public void findByUsernameWhenClearCredentialsThenFindByUsernameStillHasCredentials() {
		User foundUser = users.findByUsername(USERNAME).cast(User.class).block();
		assertThat(foundUser.getPassword()).isNotEmpty();
		foundUser.eraseCredentials();
		assertThat(foundUser.getPassword()).isNull();

		foundUser = users.findByUsername(USERNAME).cast(User.class).block();
		assertThat(foundUser.getPassword()).isNotEmpty();
	}

	@Test
	public void findByUsernameWhenNotFoundThenEmpty() {
		assertThat((users.findByUsername("notfound"))).isEqualTo(Mono.empty());
	}

	@Test
	public void updatePassword() {
		users.updatePassword(USER_DETAILS, "newPassword").block();
		assertThat(users.findByUsername(USERNAME).block().getPassword()).isEqualTo("newPassword");
	}

	@Test
	public void createNewUser() {
		UserDetails newUser = User.withUsername("user2")
				.password("password2")
				.roles("USER")
				.build();
		users.createUser(newUser).block();
		assertThat((users.findByUsername("user2").block())).isEqualTo(newUser);
	}

	@Test(expected = IllegalArgumentException.class)
	public void createAlreadyExistingUser() {
		users.createUser(USER_DETAILS).block();
	}

	@Test
	public void updateExistingUser() {
		UserDetails updatedUser = User.withUserDetails(USER_DETAILS).roles("ADMIN").build();
		users.updateUser(updatedUser).block();
		assertThat((users.findByUsername(USERNAME).block())).isEqualTo(updatedUser);
	}

	@Test(expected = IllegalArgumentException.class)
	public void updateNonExistingUser() {
		UserDetails newUser = User.withUsername("user2")
				.password("password2")
				.roles("USER")
				.build();
		users.updateUser(newUser).block();
	}

	@Test
	public void deleteUser() {
		users.deleteUser(USERNAME).block();
		assertThat((users.findByUsername(USERNAME))).isEqualTo(Mono.empty());
	}

	@Test
	public void checkIfUserExists() {
		assertThat((users.userExists("unknown-user")).block()).isFalse();
		assertThat((users.userExists(USERNAME)).block()).isTrue();
	}

	@Test
	public void changePasswordForKnownUser() {
		Authentication authentication = new TestingAuthenticationToken(USERNAME, PASSWORD, "USER");
		users.changePassword(PASSWORD, "newPassword")
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication)).block();
		assertThat(users.findByUsername(USERNAME).block().getPassword()).isEqualTo("newPassword");
	}

	@Test(expected = IllegalStateException.class)
	public void changePasswordForUnknownUser() {
		Authentication authentication = new TestingAuthenticationToken("unknown-user", PASSWORD, "USER");
		users.changePassword(PASSWORD, "newPassword")
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication)).block();
	}

	@Test(expected = AccessDeniedException.class)
	public void changePasswordForUnauthenticatedUser() {
		users.changePassword(PASSWORD, "newPassword")
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(null)).block();
	}

	@Test(expected = BadCredentialsException.class)
	public void changePasswordIfAuthenticationFails() {
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
		users.setAuthenticationManager(authenticationManager);
		when(authenticationManager.authenticate(any(Authentication.class))).thenThrow(new BadCredentialsException(""));

		Authentication authentication = new TestingAuthenticationToken(USERNAME, PASSWORD, "USER");
		users.changePassword(PASSWORD, "newPassword")
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication)).block();
	}
}
