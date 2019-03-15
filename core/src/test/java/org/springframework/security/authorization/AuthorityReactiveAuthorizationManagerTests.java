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

package org.springframework.security.authorization;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class AuthorityReactiveAuthorizationManagerTests {
	@Mock
	Authentication authentication;

	AuthorityReactiveAuthorizationManager<Object> manager = AuthorityReactiveAuthorizationManager
		.hasAuthority("ADMIN");

	@Test
	public void checkWhenHasAuthorityAndNotAuthenticatedThenReturnFalse() {
		boolean granted = manager.check(Mono.just(authentication), null).block().isGranted();

		assertThat(granted).isFalse();
	}

	@Test
	public void checkWhenHasAuthorityAndEmptyThenReturnFalse() {
		boolean granted = manager.check(Mono.empty(), null).block().isGranted();

		assertThat(granted).isFalse();
	}

	@Test
	public void checkWhenHasAuthorityAndErrorThenError() {
		Mono<AuthorizationDecision> result = manager.check(Mono.error(new RuntimeException("ooops")), null);

		StepVerifier
			.create(result)
			.expectError()
			.verify();
	}

	@Test
	public void checkWhenHasAuthorityAndAuthenticatedAndNoAuthoritiesThenReturnFalse() {
		when(authentication.isAuthenticated()).thenReturn(true);
		when(authentication.getAuthorities()).thenReturn(Collections.emptyList());

		boolean granted = manager.check(Mono.just(authentication), null).block().isGranted();

		assertThat(granted).isFalse();
	}

	@Test
	public void checkWhenHasAuthorityAndAuthenticatedAndWrongAuthoritiesThenReturnFalse() {
		authentication = new TestingAuthenticationToken("rob", "secret", "ROLE_ADMIN");

		boolean granted = manager.check(Mono.just(authentication), null).block().isGranted();

		assertThat(granted).isFalse();
	}

	@Test
	public void checkWhenHasAuthorityAndAuthorizedThenReturnTrue() {
		authentication = new TestingAuthenticationToken("rob", "secret", "ADMIN");

		boolean granted = manager.check(Mono.just(authentication), null).block().isGranted();

		assertThat(granted).isTrue();
	}

	@Test
	public void checkWhenHasRoleAndAuthorizedThenReturnTrue() {
		manager = AuthorityReactiveAuthorizationManager.hasRole("ADMIN");
		authentication = new TestingAuthenticationToken("rob", "secret", "ROLE_ADMIN");

		boolean granted = manager.check(Mono.just(authentication), null).block().isGranted();

		assertThat(granted).isTrue();
	}

	@Test
	public void checkWhenHasRoleAndNotAuthorizedThenReturnTrue() {
		manager = AuthorityReactiveAuthorizationManager.hasRole("ADMIN");
		authentication = new TestingAuthenticationToken("rob", "secret", "ADMIN");

		boolean granted = manager.check(Mono.just(authentication), null).block().isGranted();

		assertThat(granted).isFalse();
	}

	@Test(expected = IllegalArgumentException.class)
	public void hasRoleWhenNullThenException() {
		String role = null;
		AuthorityReactiveAuthorizationManager.hasRole(role);
	}

	@Test(expected = IllegalArgumentException.class)
	public void hasAuthorityWhenNullThenException() {
		String authority = null;
		AuthorityReactiveAuthorizationManager.hasAuthority(authority);
	}
}
