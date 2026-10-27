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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.OAuth2TokenValidator;
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

		Clock clock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
		JwtIssuedAtValidator issuedAtValidator = new JwtIssuedAtValidator(true);
		issuedAtValidator.setClock(clock);
		Function<DPoPProofContext, OAuth2TokenValidator<Jwt>> validatorFactory = (context) -> issuedAtValidator;
		DPoPProofJwtDecoderFactory jwtDecoderFactory = new DPoPProofJwtDecoderFactory();
		jwtDecoderFactory.setJwtValidatorFactory(validatorFactory);

		// @formatter:off
		Map<String, Object> publicJwk = rsaJwk.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		Instant issuedAt = Instant.now(clock).minus(Duration.ofSeconds(65));		// now minus 65 seconds
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

		JwtDecoder jwtDecoder = jwtDecoderFactory.createDecoder(dPoPProofContext);

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

		Clock clock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
		JwtIssuedAtValidator issuedAtValidator = new JwtIssuedAtValidator(true);
		issuedAtValidator.setClock(clock);
		Function<DPoPProofContext, OAuth2TokenValidator<Jwt>> validatorFactory = (context) -> issuedAtValidator;
		DPoPProofJwtDecoderFactory jwtDecoderFactory = new DPoPProofJwtDecoderFactory();
		jwtDecoderFactory.setJwtValidatorFactory(validatorFactory);

		// @formatter:off
		Map<String, Object> publicJwk = rsaJwk.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		Instant issuedAt = Instant.now(clock).plus(Duration.ofSeconds(65));		// now plus 65 seconds
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

		JwtDecoder jwtDecoder = jwtDecoderFactory.createDecoder(dPoPProofContext);

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

	/**
	 * With a small {@code maxSize}, filling the cache and then submitting a new proof
	 * exercises the cache-full rejection: rather than evicting an existing entry (which
	 * could let a cached {@code jti} be replayed), the proof that cannot be cached is
	 * rejected. Replaying a proof while the cache still has room confirms replay
	 * detection. Each proof is signed with its own key so the per-key request limit is
	 * never the reason for a rejection.
	 */
	@Test
	public void decodeWhenCacheFullThenThrowBadJwtException() throws Exception {
		DPoPProofReplayValidator.InMemoryCache cache = new DPoPProofReplayValidator.InMemoryCache();
		cache.setMaxSize(3);
		cache.setMaxRequestsPerKey(3);
		DPoPProofReplayValidator replayValidator = new DPoPProofReplayValidator(cache);
		this.jwtDecoderFactory.setJwtValidatorFactory(
				DPoPProofJwtDecoderFactory.createDefaultJwtValidatorFactory(List.of(replayValidator)));

		String method = "GET";
		String targetUri = "https://resource1";
		RSAKey jwk1 = TestJwks.generateRsa().keyID("kid-1").build();
		RSAKey jwk2 = TestJwks.generateRsa().keyID("kid-2").build();
		RSAKey jwk3 = TestJwks.generateRsa().keyID("kid-3").build();
		RSAKey jwk4 = TestJwks.generateRsa().keyID("kid-4").build();
		String proof1 = createJwt(createJwtEncoder(jwk1), createJwsHeader(jwk1),
				createJwtClaims(method, targetUri, "jti-1"));
		String proof2 = createJwt(createJwtEncoder(jwk2), createJwsHeader(jwk2),
				createJwtClaims(method, targetUri, "jti-2"));
		String proof3 = createJwt(createJwtEncoder(jwk3), createJwsHeader(jwk3),
				createJwtClaims(method, targetUri, "jti-3"));
		String proof4 = createJwt(createJwtEncoder(jwk4), createJwsHeader(jwk4),
				createJwtClaims(method, targetUri, "jti-4"));

		// @formatter:off
		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(proof1)
				.method(method)
				.targetUri(targetUri)
				.build();
		// @formatter:on

		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(dPoPProofContext);

		// Two proofs are accepted and cached; the cache is not yet full
		jwtDecoder.decode(proof1);
		jwtDecoder.decode(proof2);

		// Replay detection: proof1 is still cached and there is room, so it is rejected
		assertThatExceptionOfType(BadJwtException.class).isThrownBy(() -> jwtDecoder.decode(proof1))
			.withMessageContaining("jti claim is invalid");

		// A third proof fills the cache to its configured maxSize
		jwtDecoder.decode(proof3);

		// Cache-full rejection: proof4 has an unseen jti with its own key, so it is
		// rejected because the cache is full, not by replay or the per-key limit
		assertThatExceptionOfType(BadJwtException.class).isThrownBy(() -> jwtDecoder.decode(proof4))
			.withMessageContaining("jti claim is invalid");
	}

	private static JwsHeader createJwsHeader(RSAKey rsaJwk) {
		// @formatter:off
		return JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
				.jwk(rsaJwk.toPublicJWK().toJSONObject())
				.build();
		// @formatter:on
	}

	private static JwtClaimsSet createJwtClaims(String method, String targetUri, String jti) {
		// @formatter:off
		return JwtClaimsSet.builder()
				.issuedAt(Instant.now())
				.claim("htm", method)
				.claim("htu", targetUri)
				.id(jti)
				.build();
		// @formatter:on
	}

	private static JwtEncoder createJwtEncoder(RSAKey rsaJwk) throws Exception {
		JWKSource<SecurityContext> jwkSource = mock(JWKSource.class);
		given(jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));
		return new NimbusJwtEncoder(jwkSource);
	}

	private static String createJwt(JwtEncoder jwtEncoder, JwsHeader jwsHeader, JwtClaimsSet claims) {
		return jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims)).getTokenValue();
	}

}
