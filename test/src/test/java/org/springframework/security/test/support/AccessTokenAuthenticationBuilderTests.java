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
package org.springframework.security.test.support;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Collections;

import org.junit.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @since 5.2
 */
public class AccessTokenAuthenticationBuilderTests {
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
	public void scopeClaimAreAddedToAuthorities() {
		final OAuth2IntrospectionAuthenticationToken actual = new TestAccessTokenAuthenticationBuilder().name("ch4mpy")
				.authorities("TEST_AUTHORITY")
				.claim("scope", Collections.singleton("scope:claim"))
				.build();

		assertThat(actual.getAuthorities()).containsExactlyInAnyOrder(
				new SimpleGrantedAuthority("TEST_AUTHORITY"),
				new SimpleGrantedAuthority("SCOPE_scope:claim"));
	}

}
