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

package org.springframework.security.oauth2.core.oidc;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OidcIdToken}.
 *
 * @author Joe Grandja
 */
public class OidcIdTokenTests {

	private static final String ISS_CLAIM = "iss";

	private static final String SUB_CLAIM = "sub";

	private static final String AUD_CLAIM = "aud";

	private static final String IAT_CLAIM = "iat";

	private static final String EXP_CLAIM = "exp";

	private static final String AUTH_TIME_CLAIM = "auth_time";

	private static final String NONCE_CLAIM = "nonce";

	private static final String ACR_CLAIM = "acr";

	private static final String AMR_CLAIM = "amr";

	private static final String AZP_CLAIM = "azp";

	private static final String AT_HASH_CLAIM = "at_hash";

	private static final String C_HASH_CLAIM = "c_hash";

	private static final String ISS_VALUE = "https://provider.com";

	private static final String SUB_VALUE = "subject1";

	private static final List<String> AUD_VALUE = Arrays.asList("aud1", "aud2");

	private static final long IAT_VALUE = Instant.now().toEpochMilli();

	private static final long EXP_VALUE = Instant.now().plusSeconds(60).toEpochMilli();

	private static final long AUTH_TIME_VALUE = Instant.now().minusSeconds(5).toEpochMilli();

	private static final String NONCE_VALUE = "nonce";

	private static final String ACR_VALUE = "acr";

	private static final List<String> AMR_VALUE = Arrays.asList("amr1", "amr2");

	private static final String AZP_VALUE = "azp";

	private static final String AT_HASH_VALUE = "at_hash";

	private static final String C_HASH_VALUE = "c_hash";

	private static final Map<String, Object> CLAIMS;

	private static final String ID_TOKEN_VALUE = "id-token-value";
	static {
		CLAIMS = new HashMap<>();
		CLAIMS.put(ISS_CLAIM, ISS_VALUE);
		CLAIMS.put(SUB_CLAIM, SUB_VALUE);
		CLAIMS.put(AUD_CLAIM, AUD_VALUE);
		CLAIMS.put(IAT_CLAIM, IAT_VALUE);
		CLAIMS.put(EXP_CLAIM, EXP_VALUE);
		CLAIMS.put(AUTH_TIME_CLAIM, AUTH_TIME_VALUE);
		CLAIMS.put(NONCE_CLAIM, NONCE_VALUE);
		CLAIMS.put(ACR_CLAIM, ACR_VALUE);
		CLAIMS.put(AMR_CLAIM, AMR_VALUE);
		CLAIMS.put(AZP_CLAIM, AZP_VALUE);
		CLAIMS.put(AT_HASH_CLAIM, AT_HASH_VALUE);
		CLAIMS.put(C_HASH_CLAIM, C_HASH_VALUE);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenTokenValueIsNullThenThrowIllegalArgumentException() {
		new OidcIdToken(null, Instant.ofEpochMilli(IAT_VALUE), Instant.ofEpochMilli(EXP_VALUE), CLAIMS);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenClaimsIsEmptyThenThrowIllegalArgumentException() {
		new OidcIdToken(ID_TOKEN_VALUE, Instant.ofEpochMilli(IAT_VALUE), Instant.ofEpochMilli(EXP_VALUE),
				Collections.emptyMap());
	}

	@Test
	public void constructorWhenParametersProvidedAndValidThenCreated() {
		OidcIdToken idToken = new OidcIdToken(ID_TOKEN_VALUE, Instant.ofEpochMilli(IAT_VALUE),
				Instant.ofEpochMilli(EXP_VALUE), CLAIMS);
		assertThat(idToken.getClaims()).isEqualTo(CLAIMS);
		assertThat(idToken.getTokenValue()).isEqualTo(ID_TOKEN_VALUE);
		assertThat(idToken.getIssuer().toString()).isEqualTo(ISS_VALUE);
		assertThat(idToken.getSubject()).isEqualTo(SUB_VALUE);
		assertThat(idToken.getAudience()).isEqualTo(AUD_VALUE);
		assertThat(idToken.getIssuedAt().toEpochMilli()).isEqualTo(IAT_VALUE);
		assertThat(idToken.getExpiresAt().toEpochMilli()).isEqualTo(EXP_VALUE);
		assertThat(idToken.getAuthenticatedAt().getEpochSecond()).isEqualTo(AUTH_TIME_VALUE);
		assertThat(idToken.getNonce()).isEqualTo(NONCE_VALUE);
		assertThat(idToken.getAuthenticationContextClass()).isEqualTo(ACR_VALUE);
		assertThat(idToken.getAuthenticationMethods()).isEqualTo(AMR_VALUE);
		assertThat(idToken.getAuthorizedParty()).isEqualTo(AZP_VALUE);
		assertThat(idToken.getAccessTokenHash()).isEqualTo(AT_HASH_VALUE);
		assertThat(idToken.getAuthorizationCodeHash()).isEqualTo(C_HASH_VALUE);
	}

}
