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

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link OidcUserAuthority}.
 *
 * @author Joe Grandja
 */
public class OidcUserAuthorityTests {

	private static final String AUTHORITY = "ROLE_USER";

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
	private static final OidcIdToken ID_TOKEN = new OidcIdToken("id-token-value", Instant.EPOCH, Instant.MAX,
			ID_TOKEN_CLAIMS);

	private static final OidcUserInfo USER_INFO = new OidcUserInfo(USER_INFO_CLAIMS);

	@Test
	public void constructorWhenIdTokenIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new OidcUserAuthority(null));
	}

	@Test
	public void constructorWhenUserInfoIsNullThenDoesNotThrowAnyException() {
		new OidcUserAuthority(ID_TOKEN, null);
	}

	@Test
	public void constructorWhenAuthorityIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new OidcUserAuthority(null, ID_TOKEN, USER_INFO));
	}

	@Test
	public void constructorWhenAllParametersProvidedAndValidThenCreated() {
		OidcUserAuthority userAuthority = new OidcUserAuthority(AUTHORITY, ID_TOKEN, USER_INFO);
		assertThat(userAuthority.getIdToken()).isEqualTo(ID_TOKEN);
		assertThat(userAuthority.getUserInfo()).isEqualTo(USER_INFO);
		assertThat(userAuthority.getAuthority()).isEqualTo(AUTHORITY);
		assertThat(userAuthority.getAttributes()).containsOnlyKeys(IdTokenClaimNames.ISS, IdTokenClaimNames.SUB,
				StandardClaimNames.NAME, StandardClaimNames.EMAIL);
	}

}
