/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.authentication;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link OAuth2TokenExchangeSubjectTokenContext}.
 *
 * @author Bapuji Koraganti
 */
public class OAuth2TokenExchangeSubjectTokenContextTests {

	@Test
	public void constructorWhenPrincipalNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2TokenExchangeSubjectTokenContext(
						null, "user", Collections.emptyMap(), Collections.emptySet()))
				.withMessage("principal cannot be null");
		// @formatter:on
	}

	@Test
	public void constructorWhenPrincipalNameEmptyThenThrowIllegalArgumentException() {
		Authentication principal = new TestingAuthenticationToken("user", null);
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2TokenExchangeSubjectTokenContext(
						principal, "", Collections.emptyMap(), Collections.emptySet()))
				.withMessage("principalName cannot be empty");
		// @formatter:on
	}

	@Test
	public void constructorWhenClaimsNullThenThrowIllegalArgumentException() {
		Authentication principal = new TestingAuthenticationToken("user", null);
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2TokenExchangeSubjectTokenContext(
						principal, "user", null, Collections.emptySet()))
				.withMessage("claims cannot be null");
		// @formatter:on
	}

	@Test
	public void constructorWhenScopesNullThenThrowIllegalArgumentException() {
		Authentication principal = new TestingAuthenticationToken("user", null);
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2TokenExchangeSubjectTokenContext(
						principal, "user", Collections.emptyMap(), null))
				.withMessage("scopes cannot be null");
		// @formatter:on
	}

	@Test
	public void constructorWhenValidParametersThenContextCreated() {
		Authentication principal = new TestingAuthenticationToken("user", null);
		Map<String, Object> claims = Map.of("iss", "https://gitlab.com", "sub", "user");
		Set<String> scopes = Set.of("read", "write");

		OAuth2TokenExchangeSubjectTokenContext context = new OAuth2TokenExchangeSubjectTokenContext(principal, "user",
				claims, scopes);

		assertThat(context.getPrincipal()).isSameAs(principal);
		assertThat(context.getPrincipalName()).isEqualTo("user");
		assertThat(context.getClaims()).isEqualTo(claims);
		assertThat(context.getScopes()).isEqualTo(scopes);
	}

}
