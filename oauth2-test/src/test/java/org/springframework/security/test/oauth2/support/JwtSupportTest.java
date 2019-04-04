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
import java.util.Map;

import org.junit.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 */
public class JwtSupportTest {

	@Test
	public void authenticationNameAndTokenSubjectClaimAreSet() {
		final JwtAuthenticationToken actual = JwtSupport.authentication(
				"ch4mpy",
				Collections.emptySet(),
				Collections.emptySet(),
				Collections.emptyMap(),
				JwtSupport.DEFAULT_HEADERS);

		assertThat(actual.getName()).isEqualTo("ch4mpy");
		assertThat(actual.getTokenAttributes().get(JwtClaimNames.SUB)).isEqualTo("ch4mpy");
	}

	@Test
	public void tokenIatIsSetFromClaims() {
		final Map<String, Object> claims =
				Collections.singletonMap(JwtClaimNames.IAT, Instant.parse("2019-03-21T13:52:25Z"));
		final Jwt actual =
				JwtSupport
						.authentication(
								"ch4mpy",
								Collections.emptySet(),
								Collections.emptySet(),
								claims,
								JwtSupport.DEFAULT_HEADERS)
						.getToken();

		assertThat(actual.getIssuedAt()).isEqualTo(Instant.parse("2019-03-21T13:52:25Z"));
		assertThat(actual.getExpiresAt()).isNull();
		assertThat(actual.getClaimAsInstant(JwtClaimNames.IAT)).isEqualTo(Instant.parse("2019-03-21T13:52:25Z"));
		assertThat(actual.getClaimAsInstant(JwtClaimNames.EXP)).isNull();
	}

	@Test
	public void tokenExpIsSetFromClaims() {
		final Jwt actual =
				JwtSupport
						.authentication(
								"ch4mpy",
								Collections.emptySet(),
								Collections.emptySet(),
								Collections.singletonMap(JwtClaimNames.EXP, Instant.parse("2019-03-21T13:52:25Z")),
								JwtSupport.DEFAULT_HEADERS)
						.getToken();

		assertThat(actual.getIssuedAt()).isNull();
		assertThat(actual.getExpiresAt()).isEqualTo(Instant.parse("2019-03-21T13:52:25Z"));
		assertThat(actual.getClaimAsInstant(JwtClaimNames.IAT)).isNull();
		assertThat(actual.getClaimAsInstant(JwtClaimNames.EXP)).isEqualTo(Instant.parse("2019-03-21T13:52:25Z"));
	}

	@Test
	public void scopesCollectionAndScopeClaimAreAddedToAuthorities() {
		final JwtAuthenticationToken actual = JwtSupport.authentication(
				"ch4mpy",
				Collections.singleton("TEST_AUTHORITY"),
				Collections.singleton("scope:collection"),
				Collections.singletonMap("scope", Collections.singleton("scope:claim")),
				JwtSupport.DEFAULT_HEADERS);

		assertThat(actual.getAuthorities()).containsExactlyInAnyOrder(
				new SimpleGrantedAuthority("TEST_AUTHORITY"),
				new SimpleGrantedAuthority("SCOPE_scope:collection"),
				new SimpleGrantedAuthority("SCOPE_scope:claim"));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void scopesCollectionAndScopeAuthoritiesAreAddedToScopeClaim() {
		final JwtAuthenticationToken actual = JwtSupport.authentication(
				"ch4mpy",
				Collections.singleton("SCOPE_scope:authority"),
				Collections.singleton("scope:collection"),
				Collections.singletonMap("scope", Collections.singleton("scope:claim")),
				JwtSupport.DEFAULT_HEADERS);

		assertThat((Collection<String>) actual.getToken().getClaims().get("scope"))
				.containsExactlyInAnyOrder("scope:authority", "scope:collection", "scope:claim");
	}

	/**
	 * "scp" is the an usual name for "scope" claim
	 */

	@Test
	public void scopesCollectionAndScpClaimAreAddedToAuthorities() {
		final JwtAuthenticationToken actual = JwtSupport.authentication(
				"ch4mpy",
				Collections.singleton("TEST_AUTHORITY"),
				Collections.singleton("scope:collection"),
				Collections.singletonMap("scp", Collections.singleton("scope:claim")),
				JwtSupport.DEFAULT_HEADERS);

		assertThat(actual.getAuthorities()).containsExactlyInAnyOrder(
				new SimpleGrantedAuthority("TEST_AUTHORITY"),
				new SimpleGrantedAuthority("SCOPE_scope:collection"),
				new SimpleGrantedAuthority("SCOPE_scope:claim"));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void scopesCollectionAndScopeAuthoritiesAreAddedToScpClaim() {
		final JwtAuthenticationToken actual = JwtSupport.authentication(
				"ch4mpy",
				Collections.singleton("SCOPE_scope:authority"),
				Collections.singleton("scope:collection"),
				Collections.singletonMap("scp", Collections.singleton("scope:claim")),
				JwtSupport.DEFAULT_HEADERS);

		assertThat((Collection<String>) actual.getToken().getClaims().get("scp"))
				.containsExactlyInAnyOrder("scope:authority", "scope:collection", "scope:claim");
	}

}
