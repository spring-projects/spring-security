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
package org.springframework.security.oauth2.jwt;

import org.junit.Test;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;

/**
 * Tests for {@link NimbusJwtDecoderJwkSupport}.
 *
 * @author Joe Grandja
 */
public class NimbusJwtDecoderJwkSupportTests {
	private static final String JWK_SET_URL = "https://provider.com/oauth2/keys";
	private static final String JWS_ALGORITHM = JwsAlgorithms.RS256;

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenJwkSetUrlIsNullThenThrowIllegalArgumentException() {
		new NimbusJwtDecoderJwkSupport(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenJwkSetUrlInvalidThenThrowIllegalArgumentException() {
		new NimbusJwtDecoderJwkSupport("invalid.com");
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenJwsAlgorithmIsNullThenThrowIllegalArgumentException() {
		new NimbusJwtDecoderJwkSupport(JWK_SET_URL, null);
	}

	@Test(expected = JwtException.class)
	public void decodeWhenJwtInvalidThenThrowJwtException() {
		NimbusJwtDecoderJwkSupport jwtDecoder = new NimbusJwtDecoderJwkSupport(JWK_SET_URL, JWS_ALGORITHM);
		jwtDecoder.decode("invalid");
	}
}
