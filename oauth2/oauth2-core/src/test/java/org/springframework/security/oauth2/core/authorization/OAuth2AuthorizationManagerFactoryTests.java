/*
 * Copyright 2025-present the original author or authors.
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

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagerFactories;
import org.springframework.security.authorization.AuthorizationResult;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OAuth2AuthorizationManagerFactory}.
 *
 * @author Ngoc Nhan
 */
public class OAuth2AuthorizationManagerFactoryTests {

	@Test
	public void hasScopeReturnsAuthorityAuthorizationManagerByDefault() {
		OAuth2AuthorizationManagerFactory<String> factory = new DefaultOAuth2AuthorizationManagerFactory<>();
		AuthorizationManager<String> authorizationManager = factory.hasScope("message:read");
		assertThat(authorizationManager).isInstanceOf(AuthorityAuthorizationManager.class);
	}

	@Test
	public void hasAnyScopeReturnsAuthorityAuthorizationManagerByDefault() {
		OAuth2AuthorizationManagerFactory<String> factory = new DefaultOAuth2AuthorizationManagerFactory<>();
		AuthorizationManager<String> authorizationManager = factory.hasAnyScope("message:read", "message:write");
		assertThat(authorizationManager).isInstanceOf(AuthorityAuthorizationManager.class);
	}

	@Test
	public void hasScopeWhenSetAuthorizationManagerFactories() {
		DefaultOAuth2AuthorizationManagerFactory<String> factory = new DefaultOAuth2AuthorizationManagerFactory<>(
				AuthorizationManagerFactories.<String>multiFactor().requireFactors("SCOPE_message:read").build());
		assertUserGranted(factory.hasScope("message:read"));
		assertUserDenied(factory.hasScope("message:write"));
	}

	@Test
	public void hasAnyScopeWhenSetAuthorizationManagerFactories() {
		DefaultOAuth2AuthorizationManagerFactory<String> factory = new DefaultOAuth2AuthorizationManagerFactory<>(
				AuthorizationManagerFactories.<String>multiFactor().requireFactors("SCOPE_message:read").build());
		assertUserGranted(factory.hasAnyScope("message:read"));
		assertUserDenied(factory.hasAnyScope("message:write"));
	}

	private void assertUserGranted(AuthorizationManager<String> manager) {
		AuthorizationResult authorizationResult = createAuthorizationResult(manager);
		assertThat(authorizationResult).isNotNull();
		assertThat(authorizationResult.isGranted()).isTrue();
	}

	private void assertUserDenied(AuthorizationManager<String> manager) {
		AuthorizationResult authorizationResult = createAuthorizationResult(manager);
		assertThat(authorizationResult).isNotNull();
		assertThat(authorizationResult.isGranted()).isFalse();
	}

	private AuthorizationResult createAuthorizationResult(AuthorizationManager<String> manager) {
		TestingAuthenticationToken authenticatedUser = new TestingAuthenticationToken("user", "pass",
				"SCOPE_message:read");
		return manager.authorize(() -> authenticatedUser, "");
	}

}
