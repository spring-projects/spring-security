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

package org.springframework.security.oauth2.core;

import org.junit.jupiter.api.Test;

import org.springframework.security.authorization.AuthorityAuthorizationManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link OAuth2AuthorizationManagers}
 *
 * @author Mario Petrovski
 */
public class OAuth2AuthorizationManagersTests {

	@Test
	void hasScope_withInvalidScope_shouldThrowIllegalArgumentException() {
		String scope = "SCOPE_invalid";
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> OAuth2AuthorizationManagers.hasScope(scope))
				.withMessage("Scope 'SCOPE_invalid' start with 'SCOPE_' prefix.");
	}

	@Test
	void hasScopes_withInvalidScope_shouldThrowIllegalArgumentException() {
		String[] scopes = { "read", "write", "SCOPE_invalid" };
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> OAuth2AuthorizationManagers.hasAnyScope(scopes))
				.withMessage("Scope 'SCOPE_invalid' start with 'SCOPE_' prefix.");
	}

	@Test
	void hasScope_withValidScope_shouldPass() {
		String scope = "read";
		AuthorityAuthorizationManager<Object> authorizationManager = OAuth2AuthorizationManagers.hasScope(scope);
		assertThat(authorizationManager).isNotNull();
	}

	@Test
	void hasScope_withValidScopes_shouldPass() {
		String[] scopes = { "read", "write" };
		AuthorityAuthorizationManager<Object> authorizationManager = OAuth2AuthorizationManagers.hasAnyScope(scopes);
		assertThat(authorizationManager).isNotNull();
	}

}
