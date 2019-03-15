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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatCode;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;

/**
 * Tests for {@link NimbusJwtDecoderJwkSupport}.
 *
 * @author Joe Grandja
 * @author Josh Cummings
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({NimbusJwtDecoderJwkSupport.class, JWTParser.class})
public class NimbusJwtDecoderJwkSupportTests {
	private static final String JWK_SET_URL = "https://provider.com/oauth2/keys";
	private static final String JWS_ALGORITHM = JwsAlgorithms.RS256;

	private String unsignedToken = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJleHAiOi0yMDMzMjI0OTcsImp0aSI6IjEyMyIsInR5cCI6IkpXVCJ9.";

	@Test
	public void constructorWhenJwkSetUrlIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new NimbusJwtDecoderJwkSupport(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenJwkSetUrlInvalidThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new NimbusJwtDecoderJwkSupport("invalid.com"))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenJwsAlgorithmIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new NimbusJwtDecoderJwkSupport(JWK_SET_URL, null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void decodeWhenJwtInvalidThenThrowJwtException() {
		NimbusJwtDecoderJwkSupport jwtDecoder = new NimbusJwtDecoderJwkSupport(JWK_SET_URL, JWS_ALGORITHM);
		assertThatThrownBy(() -> jwtDecoder.decode("invalid"))
				.isInstanceOf(JwtException.class);
	}

	// gh-5168
	@Test
	public void decodeWhenExpClaimNullThenDoesNotThrowException() throws Exception {
		SignedJWT jwt = mock(SignedJWT.class);
		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.parse(JWS_ALGORITHM)).build();
		when(jwt.getHeader()).thenReturn(header);

		mockStatic(JWTParser.class);
		when(JWTParser.parse(anyString())).thenReturn(jwt);

		DefaultJWTProcessor jwtProcessor = mock(DefaultJWTProcessor.class);
		whenNew(DefaultJWTProcessor.class).withAnyArguments().thenReturn(jwtProcessor);

		JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder().audience("resource1").build();
		when(jwtProcessor.process(any(JWT.class), eq(null))).thenReturn(jwtClaimsSet);

		NimbusJwtDecoderJwkSupport jwtDecoder = new NimbusJwtDecoderJwkSupport(JWK_SET_URL, JWS_ALGORITHM);
		assertThatCode(() -> jwtDecoder.decode("encoded-jwt")).doesNotThrowAnyException();
	}

	// gh-5457
	@Test
	public void decodeWhenPlainJwtThenExceptionDoesNotMentionClass() throws Exception {
		NimbusJwtDecoderJwkSupport jwtDecoder = new NimbusJwtDecoderJwkSupport(JWK_SET_URL, JWS_ALGORITHM);

		assertThatCode(() -> jwtDecoder.decode(this.unsignedToken))
				.isInstanceOf(JwtException.class)
				.hasMessageContaining("Unsupported algorithm of none");
	}
}
