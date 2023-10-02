/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.oauth2.core.authorization;

import org.junit.jupiter.api.Test;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link OAuth2AuthorizationManagers}
 *
 * @author Mario Petrovski
 * @author Josh Cummings
 */
public class OAuth2AuthorizationManagersTests {

	@Test
	void hasScopeWhenInvalidScopeThenThrowIllegalArgument() {
		String scope = "SCOPE_invalid";
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> OAuth2AuthorizationManagers.hasScope(scope))
			.withMessageContaining("SCOPE_invalid should not start with SCOPE_");
	}

	@Test
	void hasAnyScopeWhenInvalidScopeThenThrowIllegalArgument() {
		String[] scopes = { "read", "write", "SCOPE_invalid" };
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> OAuth2AuthorizationManagers.hasAnyScope(scopes))
			.withMessageContaining("SCOPE_invalid should not start with SCOPE_");
	}

	@Test
	void hasScopeWhenValidScopeThenAuthorizationManager() {
		String scope = "read";
		AuthorizationManager<Object> authorizationManager = OAuth2AuthorizationManagers.hasScope(scope);
		authorizationManager.verify(() -> hasScope(scope), new Object());
		assertThatExceptionOfType(AccessDeniedException.class)
			.isThrownBy(() -> authorizationManager.verify(() -> hasScope("wrong"), new Object()));
	}

	@Test
	void hasAnyScopeWhenValidScopesThenAuthorizationManager() {
		String[] scopes = { "read", "write" };
		AuthorizationManager<Object> authorizationManager = OAuth2AuthorizationManagers.hasAnyScope(scopes);
		for (String scope : scopes) {
			authorizationManager.verify(() -> hasScope(scope), new Object());
		}
		assertThatExceptionOfType(AccessDeniedException.class)
			.isThrownBy(() -> authorizationManager.verify(() -> hasScope("wrong"), new Object()));
	}

	Authentication hasScope(String scope) {
		return new TestingAuthenticationToken("user", "pass", "SCOPE_" + scope);
	}

}
