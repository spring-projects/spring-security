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

import org.springframework.security.authorization.AuthorityAuthorizationManager;

/**
 * @author Mario Petrovski
 * @since 6.2
 */
public final class OAuth2AuthorizationManagers {

	private OAuth2AuthorizationManagers() {
	}

	public static <T> AuthorityAuthorizationManager<T> hasScope(String scope) {
		verifyScope(scope);
		return AuthorityAuthorizationManager.hasAuthority("SCOPE_" + scope);
	}

	public static <T> AuthorityAuthorizationManager<T> hasAnyScope(String... scopes) {
		verifyScopes(scopes);
		String[] mappedScopes = new String[scopes.length];
		for (int i = 0; i < scopes.length; i++) {
			mappedScopes[i] = "SCOPE_" + scopes[i];
		}
		return AuthorityAuthorizationManager.hasAnyAuthority(mappedScopes);
	}

	private static void verifyScopes(String... scopes) throws IllegalArgumentException {
		for (String scope : scopes) {
			verifyScope(scope);
		}
	}

	private static void verifyScope(String scope) {
		if (scope.startsWith("SCOPE_")) {
			throw new IllegalArgumentException("Scope '" + scope + "' start with 'SCOPE_' prefix.");
		}
	}

}
