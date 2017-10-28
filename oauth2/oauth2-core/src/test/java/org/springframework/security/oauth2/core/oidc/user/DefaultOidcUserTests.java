/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.core.oidc.user;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link DefaultOidcUser}.
 *
 * @author Vedran Pavic
 */
public class DefaultOidcUserTests {

	private static final SimpleGrantedAuthority TEST_AUTHORITY = new SimpleGrantedAuthority("ROLE_USER");

	private static final Set<GrantedAuthority> TEST_AUTHORITIES = Collections.singleton(TEST_AUTHORITY);

	private static final String TEST_SUBJECT = "test";

	private static final String TEST_EMAIL = "test@example.com";

	private static final Map<String, Object> TEST_ID_TOKEN_CLAIMS = new HashMap<>();

	static {
		TEST_ID_TOKEN_CLAIMS.put(IdTokenClaimNames.ISS, "https://example.com");
		TEST_ID_TOKEN_CLAIMS.put(IdTokenClaimNames.SUB, TEST_SUBJECT);
	}

	private static final OidcIdToken TEST_ID_TOKEN = new OidcIdToken("value", Instant.EPOCH, Instant.MAX, TEST_ID_TOKEN_CLAIMS);

	private static final OidcUserInfo TEST_USER_INFO = new OidcUserInfo(Collections.singletonMap(StandardClaimNames.EMAIL, TEST_EMAIL));

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Test
	public void constructorWhenAuthoritiesAndIdTokenThenIsCreated() {
		DefaultOidcUser user = new DefaultOidcUser(TEST_AUTHORITIES, TEST_ID_TOKEN);

		assertThat(user.getName()).isEqualTo(TEST_SUBJECT);
		assertThat(user.getAuthorities()).hasSize(1);
		assertThat(user.getAuthorities().iterator().next()).isEqualTo(TEST_AUTHORITY);
		assertThat(user.getAttributes()).containsOnlyKeys(IdTokenClaimNames.ISS, IdTokenClaimNames.SUB);
	}

	@Test
	public void constructorWhenAuthoritiesAndIdTokenAndNameAttributeKeyThenIsCreated() {
		DefaultOidcUser user = new DefaultOidcUser(TEST_AUTHORITIES, TEST_ID_TOKEN, IdTokenClaimNames.SUB);

		assertThat(user.getName()).isEqualTo(TEST_SUBJECT);
		assertThat(user.getAuthorities()).hasSize(1);
		assertThat(user.getAuthorities().iterator().next()).isEqualTo(TEST_AUTHORITY);
		assertThat(user.getAttributes()).containsOnlyKeys(IdTokenClaimNames.ISS, IdTokenClaimNames.SUB);
	}

	@Test
	public void constructorWhenAuthoritiesAndIdTokenAndUserInfoThenIsCreated() {
		DefaultOidcUser user = new DefaultOidcUser(TEST_AUTHORITIES, TEST_ID_TOKEN, TEST_USER_INFO);

		assertThat(user.getName()).isEqualTo(TEST_SUBJECT);
		assertThat(user.getAuthorities()).hasSize(1);
		assertThat(user.getAuthorities().iterator().next()).isEqualTo(TEST_AUTHORITY);
		assertThat(user.getAttributes()).containsOnlyKeys(IdTokenClaimNames.ISS, IdTokenClaimNames.SUB, StandardClaimNames.EMAIL);
	}

	@Test
	public void constructorWhenAuthoritiesAndIdTokenAndUserInfoAndNameAttributeKeyThenIsCreated() {
		DefaultOidcUser user = new DefaultOidcUser(TEST_AUTHORITIES, TEST_ID_TOKEN, TEST_USER_INFO, StandardClaimNames.EMAIL);

		assertThat(user.getName()).isEqualTo(TEST_EMAIL);
		assertThat(user.getAuthorities()).hasSize(1);
		assertThat(user.getAuthorities().iterator().next()).isEqualTo(TEST_AUTHORITY);
		assertThat(user.getAttributes()).containsOnlyKeys(IdTokenClaimNames.ISS, IdTokenClaimNames.SUB, StandardClaimNames.EMAIL);
	}

	@Test
	public void constructorWhenIdTokenIsNullThenThrowsException() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("idToken cannot be null");

		new DefaultOidcUser(TEST_AUTHORITIES, null);
	}

	@Test
	public void constructorWhenNameAttributeKeyClaimIsNotPresentThenThrowsException() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Missing attribute '" + StandardClaimNames.NAME + "' in attributes");

		new DefaultOidcUser(TEST_AUTHORITIES, TEST_ID_TOKEN, TEST_USER_INFO, StandardClaimNames.NAME);
	}

}
