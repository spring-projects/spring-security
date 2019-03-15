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
package org.springframework.security.oauth2.jwt;

import org.junit.Test;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link Jwt}.
 *
 * @author Joe Grandja
 */
public class JwtTests {
	private static final String ISS_CLAIM = "iss";
	private static final String SUB_CLAIM = "sub";
	private static final String AUD_CLAIM = "aud";
	private static final String EXP_CLAIM = "exp";
	private static final String NBF_CLAIM = "nbf";
	private static final String IAT_CLAIM = "iat";
	private static final String JTI_CLAIM = "jti";

	private static final String ISS_VALUE = "https://provider.com";
	private static final String SUB_VALUE = "subject1";
	private static final List<String> AUD_VALUE = Arrays.asList("aud1", "aud2");
	private static final long EXP_VALUE = Instant.now().plusSeconds(60).toEpochMilli();
	private static final long NBF_VALUE = Instant.now().plusSeconds(5).toEpochMilli();
	private static final long IAT_VALUE = Instant.now().toEpochMilli();
	private static final String JTI_VALUE = "jwt-id-1";

	private static final Map<String, Object> HEADERS;
	private static final Map<String, Object> CLAIMS;
	private static final String JWT_TOKEN_VALUE = "jwt-token-value";

	static {
		HEADERS = new HashMap<>();
		HEADERS.put("alg", JwsAlgorithms.RS256);

		CLAIMS = new HashMap<>();
		CLAIMS.put(ISS_CLAIM, ISS_VALUE);
		CLAIMS.put(SUB_CLAIM, SUB_VALUE);
		CLAIMS.put(AUD_CLAIM, AUD_VALUE);
		CLAIMS.put(EXP_CLAIM, EXP_VALUE);
		CLAIMS.put(NBF_CLAIM, NBF_VALUE);
		CLAIMS.put(IAT_CLAIM, IAT_VALUE);
		CLAIMS.put(JTI_CLAIM, JTI_VALUE);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenTokenValueIsNullThenThrowIllegalArgumentException() {
		new Jwt(null, Instant.ofEpochMilli(IAT_VALUE), Instant.ofEpochMilli(EXP_VALUE), HEADERS, CLAIMS);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenHeadersIsEmptyThenThrowIllegalArgumentException() {
		new Jwt(JWT_TOKEN_VALUE, Instant.ofEpochMilli(IAT_VALUE),
			Instant.ofEpochMilli(EXP_VALUE), Collections.emptyMap(), CLAIMS);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenClaimsIsEmptyThenThrowIllegalArgumentException() {
		new Jwt(JWT_TOKEN_VALUE, Instant.ofEpochMilli(IAT_VALUE),
			Instant.ofEpochMilli(EXP_VALUE), HEADERS, Collections.emptyMap());
	}

	@Test
	public void constructorWhenParametersProvidedAndValidThenCreated() {
		Jwt jwt = new Jwt(JWT_TOKEN_VALUE, Instant.ofEpochMilli(IAT_VALUE),
			Instant.ofEpochMilli(EXP_VALUE), HEADERS, CLAIMS);

		assertThat(jwt.getTokenValue()).isEqualTo(JWT_TOKEN_VALUE);
		assertThat(jwt.getHeaders()).isEqualTo(HEADERS);
		assertThat(jwt.getClaims()).isEqualTo(CLAIMS);
		assertThat(jwt.getIssuer().toString()).isEqualTo(ISS_VALUE);
		assertThat(jwt.getSubject()).isEqualTo(SUB_VALUE);
		assertThat(jwt.getAudience()).isEqualTo(AUD_VALUE);
		assertThat(jwt.getExpiresAt().toEpochMilli()).isEqualTo(EXP_VALUE);
		assertThat(jwt.getNotBefore().getEpochSecond()).isEqualTo(NBF_VALUE);
		assertThat(jwt.getIssuedAt().toEpochMilli()).isEqualTo(IAT_VALUE);
		assertThat(jwt.getId()).isEqualTo(JTI_VALUE);
	}
}
