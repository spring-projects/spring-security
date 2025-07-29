/*
 * Copyright 2004-present the original author or authors.
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

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link DPoPProofJwtDecoderFactory}.
 *
 * @author Joe Grandja
 */
public class DPoPProofJwtDecoderFactoryTests {

	private JWKSource<SecurityContext> jwkSource;

	private NimbusJwtEncoder jwtEncoder;

	private DPoPProofJwtDecoderFactory jwtDecoderFactory = new DPoPProofJwtDecoderFactory();

	@BeforeEach
	public void setUp() {
		this.jwkSource = mock(JWKSource.class);
		this.jwtEncoder = new NimbusJwtEncoder(this.jwkSource);
	}

	@Test
	public void setJwtValidatorFactoryWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.jwtDecoderFactory.setJwtValidatorFactory(null))
			.withMessage("jwtValidatorFactory cannot be null");
	}

	@Test
	public void createDecoderWhenContextNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.jwtDecoderFactory.createDecoder(null))
			.withMessage("dPoPProofContext cannot be null");
	}

	@Test
	public void decodeWhenJoseTypeInvalidThenThrowBadJwtException() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		given(this.jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));

		String method = "GET";
		String targetUri = "https://resource1";

		// @formatter:off
		Map<String, Object> publicJwk = rsaJwk.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("invalid-type")
				.jwk(publicJwk)
				.build();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(Instant.now())
				.claim("htm", method)
				.claim("htu", targetUri)
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		Jwt dPoPProof = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		// @formatter:off
		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPProof.getTokenValue())
				.method(method)
				.targetUri(targetUri)
				.build();
		// @formatter:on

		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(dPoPProofContext);

		assertThatExceptionOfType(BadJwtException.class)
			.isThrownBy(() -> jwtDecoder.decode(dPoPProofContext.getDPoPProof()))
			.withMessageContaining("JOSE header typ (type) invalid-type not allowed");
	}

	@Test
	public void decodeWhenJwkMissingThenThrowBadJwtException() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		given(this.jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));

		String method = "GET";
		String targetUri = "https://resource1";

		// @formatter:off
		Map<String, Object> publicJwk = rsaJwk.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
//				.jwk(publicJwk)
				.build();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(Instant.now())
				.claim("htm", method)
				.claim("htu", targetUri)
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		Jwt dPoPProof = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		// @formatter:off
		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPProof.getTokenValue())
				.method(method)
				.targetUri(targetUri)
				.build();
		// @formatter:on

		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(dPoPProofContext);

		assertThatExceptionOfType(BadJwtException.class)
			.isThrownBy(() -> jwtDecoder.decode(dPoPProofContext.getDPoPProof()))
			.withMessageContaining("Missing jwk parameter in JWS Header.");
	}

	@Test
	public void decodeWhenMethodInvalidThenThrowBadJwtException() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		given(this.jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));

		String method = "GET";
		String targetUri = "https://resource1";

		// @formatter:off
		Map<String, Object> publicJwk = rsaJwk.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(Instant.now())
				.claim("htm", method)
				.claim("htu", targetUri)
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		Jwt dPoPProof = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		// @formatter:off
		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPProof.getTokenValue())
				.method("POST")		// Mismatch
				.targetUri(targetUri)
				.build();
		// @formatter:on

		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(dPoPProofContext);

		assertThatExceptionOfType(BadJwtException.class)
			.isThrownBy(() -> jwtDecoder.decode(dPoPProofContext.getDPoPProof()))
			.withMessageContaining("The htm claim is not valid");
	}

	@Test
	public void decodeWhenTargetUriInvalidThenThrowBadJwtException() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		given(this.jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));

		String method = "GET";
		String targetUri = "https://resource1";

		// @formatter:off
		Map<String, Object> publicJwk = rsaJwk.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(Instant.now())
				.claim("htm", method)
				.claim("htu", targetUri)
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		Jwt dPoPProof = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		// @formatter:off
		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPProof.getTokenValue())
				.method(method)
				.targetUri("https://resource2")		// Mismatch
				.build();
		// @formatter:on

		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(dPoPProofContext);

		assertThatExceptionOfType(BadJwtException.class)
			.isThrownBy(() -> jwtDecoder.decode(dPoPProofContext.getDPoPProof()))
			.withMessageContaining("The htu claim is not valid");
	}

	@Test
	public void decodeWhenJtiMissingThenThrowBadJwtException() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		given(this.jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));

		String method = "GET";
		String targetUri = "https://resource1";

		// @formatter:off
		Map<String, Object> publicJwk = rsaJwk.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(Instant.now())
				.claim("htm", method)
				.claim("htu", targetUri)
//				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		Jwt dPoPProof = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		// @formatter:off
		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPProof.getTokenValue())
				.method(method)
				.targetUri(targetUri)
				.build();
		// @formatter:on

		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(dPoPProofContext);

		assertThatExceptionOfType(BadJwtException.class)
			.isThrownBy(() -> jwtDecoder.decode(dPoPProofContext.getDPoPProof()))
			.withMessageContaining("jti claim is required");
	}

	@Test
	public void decodeWhenJtiAlreadyUsedThenThrowBadJwtException() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		given(this.jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));

		String method = "GET";
		String targetUri = "https://resource1";

		// @formatter:off
		Map<String, Object> publicJwk = rsaJwk.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(Instant.now())
				.claim("htm", method)
				.claim("htu", targetUri)
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		Jwt dPoPProof = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		// @formatter:off
		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPProof.getTokenValue())
				.method(method)
				.targetUri(targetUri)
				.build();
		// @formatter:on

		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(dPoPProofContext);

		jwtDecoder.decode(dPoPProofContext.getDPoPProof());
		assertThatExceptionOfType(BadJwtException.class)
			.isThrownBy(() -> jwtDecoder.decode(dPoPProofContext.getDPoPProof()))
			.withMessageContaining("jti claim is invalid");
	}

	@Test
	public void decodeWhenIatMissingThenThrowBadJwtException() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		given(this.jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));

		String method = "GET";
		String targetUri = "https://resource1";

		// @formatter:off
		Map<String, Object> publicJwk = rsaJwk.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		JwtClaimsSet claims = JwtClaimsSet.builder()
//				.issuedAt(Instant.now())
				.claim("htm", method)
				.claim("htu", targetUri)
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		Jwt dPoPProof = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		// @formatter:off
		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPProof.getTokenValue())
				.method(method)
				.targetUri(targetUri)
				.build();
		// @formatter:on

		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(dPoPProofContext);

		assertThatExceptionOfType(BadJwtException.class)
			.isThrownBy(() -> jwtDecoder.decode(dPoPProofContext.getDPoPProof()))
			.withMessageContaining("iat claim is required");
	}

	@Test
	public void decodeWhenIatBeforeTimeWindowThenThrowBadJwtException() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		given(this.jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));

		String method = "GET";
		String targetUri = "https://resource1";

		// @formatter:off
		Map<String, Object> publicJwk = rsaJwk.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		Instant issuedAt = Instant.now().minus(Duration.ofSeconds(65));		// now minus 65 seconds
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(issuedAt)
				.claim("htm", method)
				.claim("htu", targetUri)
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		Jwt dPoPProof = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		// @formatter:off
		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPProof.getTokenValue())
				.method(method)
				.targetUri(targetUri)
				.build();
		// @formatter:on

		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(dPoPProofContext);

		assertThatExceptionOfType(BadJwtException.class)
			.isThrownBy(() -> jwtDecoder.decode(dPoPProofContext.getDPoPProof()))
			.withMessageContaining("iat claim is invalid");
	}

	@Test
	public void decodeWhenIatAfterTimeWindowThenThrowBadJwtException() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		given(this.jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));

		String method = "GET";
		String targetUri = "https://resource1";

		// @formatter:off
		Map<String, Object> publicJwk = rsaJwk.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		Instant issuedAt = Instant.now().plus(Duration.ofSeconds(65));		// now plus 65 seconds
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(issuedAt)
				.claim("htm", method)
				.claim("htu", targetUri)
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		Jwt dPoPProof = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		// @formatter:off
		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPProof.getTokenValue())
				.method(method)
				.targetUri(targetUri)
				.build();
		// @formatter:on

		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(dPoPProofContext);

		assertThatExceptionOfType(BadJwtException.class)
			.isThrownBy(() -> jwtDecoder.decode(dPoPProofContext.getDPoPProof()))
			.withMessageContaining("iat claim is invalid");
	}

	@Test
	public void decodeWhenDPoPProofValidThenDecoded() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		given(this.jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));

		String method = "GET";
		String targetUri = "https://resource1";

		// @formatter:off
		Map<String, Object> publicJwk = rsaJwk.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(Instant.now())
				.claim("htm", method)
				.claim("htu", targetUri)
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		Jwt dPoPProof = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		// @formatter:off
		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPProof.getTokenValue())
				.method(method)
				.targetUri(targetUri)
				.build();
		// @formatter:on

		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(dPoPProofContext);
		jwtDecoder.decode(dPoPProof.getTokenValue());
	}

}
