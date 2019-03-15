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

package org.springframework.security.oauth2.core.oidc.user;

import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link DefaultOidcUser}.
 *
 * @author Vedran Pavic
 * @author Joe Grandja
 */
public class DefaultOidcUserTests {
	private static final SimpleGrantedAuthority AUTHORITY = new SimpleGrantedAuthority("ROLE_USER");
	private static final Set<GrantedAuthority> AUTHORITIES = Collections.singleton(AUTHORITY);
	private static final String SUBJECT = "test-subject";
	private static final String EMAIL = "test-subject@example.com";
	private static final String NAME = "test-name";
	private static final Map<String, Object> ID_TOKEN_CLAIMS = new HashMap<>();
	private static final Map<String, Object> USER_INFO_CLAIMS = new HashMap<>();

	static {
		ID_TOKEN_CLAIMS.put(IdTokenClaimNames.ISS, "https://example.com");
		ID_TOKEN_CLAIMS.put(IdTokenClaimNames.SUB, SUBJECT);
		USER_INFO_CLAIMS.put(StandardClaimNames.NAME, NAME);
		USER_INFO_CLAIMS.put(StandardClaimNames.EMAIL, EMAIL);
	}

	private static final OidcIdToken ID_TOKEN = new OidcIdToken("id-token-value", Instant.EPOCH, Instant.MAX, ID_TOKEN_CLAIMS);
	private static final OidcUserInfo USER_INFO = new OidcUserInfo(USER_INFO_CLAIMS);

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenAuthoritiesIsNullThenThrowIllegalArgumentException() {
		new DefaultOidcUser(null, ID_TOKEN);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenIdTokenIsNullThenThrowIllegalArgumentException() {
		new DefaultOidcUser(AUTHORITIES, null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenNameAttributeKeyInvalidThenThrowIllegalArgumentException() {
		new DefaultOidcUser(AUTHORITIES, ID_TOKEN, "invalid");
	}

	@Test
	public void constructorWhenAuthoritiesIdTokenProvidedThenCreated() {
		DefaultOidcUser user = new DefaultOidcUser(AUTHORITIES, ID_TOKEN);

		assertThat(user.getClaims()).containsOnlyKeys(IdTokenClaimNames.ISS, IdTokenClaimNames.SUB);
		assertThat(user.getIdToken()).isEqualTo(ID_TOKEN);
		assertThat(user.getName()).isEqualTo(SUBJECT);
		assertThat(user.getAuthorities()).hasSize(1);
		assertThat(user.getAuthorities().iterator().next()).isEqualTo(AUTHORITY);
		assertThat(user.getAttributes()).containsOnlyKeys(IdTokenClaimNames.ISS, IdTokenClaimNames.SUB);
	}

	@Test
	public void constructorWhenAuthoritiesIdTokenNameAttributeKeyProvidedThenCreated() {
		DefaultOidcUser user = new DefaultOidcUser(AUTHORITIES, ID_TOKEN, IdTokenClaimNames.SUB);

		assertThat(user.getClaims()).containsOnlyKeys(IdTokenClaimNames.ISS, IdTokenClaimNames.SUB);
		assertThat(user.getIdToken()).isEqualTo(ID_TOKEN);
		assertThat(user.getName()).isEqualTo(SUBJECT);
		assertThat(user.getAuthorities()).hasSize(1);
		assertThat(user.getAuthorities().iterator().next()).isEqualTo(AUTHORITY);
		assertThat(user.getAttributes()).containsOnlyKeys(IdTokenClaimNames.ISS, IdTokenClaimNames.SUB);
	}

	@Test
	public void constructorWhenAuthoritiesIdTokenUserInfoProvidedThenCreated() {
		DefaultOidcUser user = new DefaultOidcUser(AUTHORITIES, ID_TOKEN, USER_INFO);

		assertThat(user.getClaims()).containsOnlyKeys(
			IdTokenClaimNames.ISS, IdTokenClaimNames.SUB, StandardClaimNames.NAME, StandardClaimNames.EMAIL);
		assertThat(user.getIdToken()).isEqualTo(ID_TOKEN);
		assertThat(user.getUserInfo()).isEqualTo(USER_INFO);
		assertThat(user.getName()).isEqualTo(SUBJECT);
		assertThat(user.getAuthorities()).hasSize(1);
		assertThat(user.getAuthorities().iterator().next()).isEqualTo(AUTHORITY);
		assertThat(user.getAttributes()).containsOnlyKeys(
			IdTokenClaimNames.ISS, IdTokenClaimNames.SUB, StandardClaimNames.NAME, StandardClaimNames.EMAIL);
	}

	@Test
	public void constructorWhenAllParametersProvidedAndValidThenCreated() {
		DefaultOidcUser user = new DefaultOidcUser(AUTHORITIES, ID_TOKEN, USER_INFO, StandardClaimNames.EMAIL);

		assertThat(user.getClaims()).containsOnlyKeys(
			IdTokenClaimNames.ISS, IdTokenClaimNames.SUB, StandardClaimNames.NAME, StandardClaimNames.EMAIL);
		assertThat(user.getIdToken()).isEqualTo(ID_TOKEN);
		assertThat(user.getUserInfo()).isEqualTo(USER_INFO);
		assertThat(user.getName()).isEqualTo(EMAIL);
		assertThat(user.getAuthorities()).hasSize(1);
		assertThat(user.getAuthorities().iterator().next()).isEqualTo(AUTHORITY);
		assertThat(user.getAttributes()).containsOnlyKeys(
			IdTokenClaimNames.ISS, IdTokenClaimNames.SUB, StandardClaimNames.NAME, StandardClaimNames.EMAIL);
	}
}
