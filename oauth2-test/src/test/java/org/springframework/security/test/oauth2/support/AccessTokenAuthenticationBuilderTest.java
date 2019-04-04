/* Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.test.oauth2.support;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Collection;
import java.util.Collections;

import org.junit.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames;

/**
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 */
public class AccessTokenAuthenticationBuilderTest {
	static class TestAccessTokenAuthenticationBuilder
			extends
			AccessTokenAuthenticationBuilder<TestAccessTokenAuthenticationBuilder> {
	}

	@Test
	public void authenticationNameAndTokenSubjectClaimAreSet() {
		final OAuth2IntrospectionAuthenticationToken actual =
				new TestAccessTokenAuthenticationBuilder().name("ch4mpy").build();

		assertThat(actual.getName()).isEqualTo("ch4mpy");
		assertThat(actual.getTokenAttributes().get(OAuth2IntrospectionClaimNames.USERNAME)).isEqualTo("ch4mpy");
	}

	@Test
	public void tokenIatIsSetFromClaims() {
		final OAuth2AccessToken actual = new TestAccessTokenAuthenticationBuilder().name("ch4mpy")
				.claim(OAuth2IntrospectionClaimNames.ISSUED_AT, Instant.parse("2019-03-21T13:52:25Z"))
				.build()
				.getToken();

		assertThat(actual.getIssuedAt()).isEqualTo(Instant.parse("2019-03-21T13:52:25Z"));
		assertThat(actual.getExpiresAt()).isNull();
	}

	@Test
	public void tokenExpIsSetFromClaims() {
		final OAuth2AccessToken actual = new TestAccessTokenAuthenticationBuilder().name("ch4mpy")
				.claim(OAuth2IntrospectionClaimNames.EXPIRES_AT, Instant.parse("2019-03-21T13:52:25Z"))
				.build()
				.getToken();

		assertThat(actual.getIssuedAt()).isNull();
		assertThat(actual.getExpiresAt()).isEqualTo(Instant.parse("2019-03-21T13:52:25Z"));
	}

	@Test
	public void scopesCollectionAndScopeClaimAreAddedToAuthorities() {
		final OAuth2IntrospectionAuthenticationToken actual = new TestAccessTokenAuthenticationBuilder().name("ch4mpy")
				.authorities("TEST_AUTHORITY")
				.scopes("scope:collection")
				.claim("scope", Collections.singleton("scope:claim"))
				.build();

		assertThat(actual.getAuthorities()).containsExactlyInAnyOrder(
				new SimpleGrantedAuthority("TEST_AUTHORITY"),
				new SimpleGrantedAuthority("SCOPE_scope:collection"),
				new SimpleGrantedAuthority("SCOPE_scope:claim"));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void scopesCollectionAndScopeAuthoritiesAreAddedToScopeClaim() {
		final OAuth2IntrospectionAuthenticationToken actual = new TestAccessTokenAuthenticationBuilder().name("ch4mpy")
				.authorities("SCOPE_scope:authority")
				.scope("scope:collection")
				.claim("scope", Collections.singleton("scope:claim"))
				.build();

		assertThat((Collection<String>) actual.getTokenAttributes().get("scope"))
				.containsExactlyInAnyOrder("scope:authority", "scope:collection", "scope:claim");
	}

	/**
	 * "scp" is the an usual name for "scope" claim
	 */

	@Test
	public void scopesCollectionAndScpClaimAreAddedToAuthorities() {
		final OAuth2IntrospectionAuthenticationToken actual = new TestAccessTokenAuthenticationBuilder().name("ch4mpy")
				.authorities("TEST_AUTHORITY")
				.scopes("scope:collection")
				.claim("scp", Collections.singleton("scope:claim"))
				.scopesClaimName("scp")
				.build();

		assertThat(actual.getAuthorities()).containsExactlyInAnyOrder(
				new SimpleGrantedAuthority("TEST_AUTHORITY"),
				new SimpleGrantedAuthority("SCOPE_scope:collection"),
				new SimpleGrantedAuthority("SCOPE_scope:claim"));
	}

}
