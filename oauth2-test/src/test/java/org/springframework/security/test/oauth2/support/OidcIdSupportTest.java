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
import java.util.Collections;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames;

/**
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 */
public class OidcIdSupportTest {
	private static final String CLIENT_ID = "test-client";
	TestOidcIdAuthenticationBuilder builder;

	static class TestOidcIdAuthenticationBuilder
			extends
			OidcIdTokenAuthenticationBuilder<TestOidcIdAuthenticationBuilder> {
		public TestOidcIdAuthenticationBuilder() {
			super(AuthorizationGrantType.AUTHORIZATION_CODE);
		}
	}

	@Before
	public void setUp() {
		builder = new TestOidcIdAuthenticationBuilder().name("ch4mpy").nameAttributeKey("userName").role("USER");
		builder.clientRegistrationBuilder.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.clientId(CLIENT_ID)
				.tokenUri("https://stub");
		builder.authorizationRequestBuilder.authorizationUri("https://stub")
				.clientId(CLIENT_ID)
				.redirectUri("https://stub");
	}

	@Test
	public void authenticationNameIsSet() {
		final OAuth2LoginAuthenticationToken actual = builder.build();

		assertThat(actual.getName()).isEqualTo("ch4mpy");
	}

	@Test
	public void tokenIatIsSetFromClaims() {
		final OAuth2AccessToken actual =
				builder.claim(OAuth2IntrospectionClaimNames.ISSUED_AT, Instant.parse("2019-03-21T13:52:25Z"))
						.build()
						.getAccessToken();

		assertThat(actual.getIssuedAt()).isEqualTo(Instant.parse("2019-03-21T13:52:25Z"));
		assertThat(actual.getExpiresAt()).isNull();
	}

	@Test
	public void tokenExpIsSetFromClaims() {
		final OAuth2AccessToken actual =
				builder.claim(OAuth2IntrospectionClaimNames.EXPIRES_AT, Instant.parse("2019-03-21T13:52:25Z"))
						.build()
						.getAccessToken();

		assertThat(actual.getIssuedAt()).isNull();
		assertThat(actual.getExpiresAt()).isEqualTo(Instant.parse("2019-03-21T13:52:25Z"));
	}

	@Test
	public void scopesCollectionAndScopeClaimAreAddedToAuthorities() {
		final OAuth2LoginAuthenticationToken actual = builder.authorities("TEST_AUTHORITY")
				.scopes("scope:collection")
				.claim("scope", Collections.singleton("scope:claim"))
				.build();

		assertThat(actual.getAuthorities()).containsExactlyInAnyOrder(
				new SimpleGrantedAuthority("TEST_AUTHORITY"),
				new SimpleGrantedAuthority("SCOPE_scope:collection"),
				new SimpleGrantedAuthority("SCOPE_scope:claim"));
	}

}
