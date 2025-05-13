/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.oauth2.server.resource.authentication;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link DPoPAuthenticationProvider}.
 *
 * @author Joe Grandja
 */
public class DPoPAuthenticationProviderTests {

	private NimbusJwtEncoder accessTokenJwtEncoder;

	private NimbusJwtEncoder dPoPProofJwtEncoder;

	private AuthenticationManager tokenAuthenticationManager;

	private DPoPAuthenticationProvider authenticationProvider;

	@BeforeEach
	public void setUp() {
		JWKSource<SecurityContext> jwkSource = (jwkSelector, securityContext) -> jwkSelector
			.select(new JWKSet(TestJwks.DEFAULT_EC_JWK));
		this.accessTokenJwtEncoder = new NimbusJwtEncoder(jwkSource);
		jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(new JWKSet(TestJwks.DEFAULT_RSA_JWK));
		this.dPoPProofJwtEncoder = new NimbusJwtEncoder(jwkSource);
		this.tokenAuthenticationManager = mock(AuthenticationManager.class);
		this.authenticationProvider = new DPoPAuthenticationProvider(this.tokenAuthenticationManager);
	}

	@Test
	public void constructorWhenTokenAuthenticationManagerNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new DPoPAuthenticationProvider(null))
			.withMessage("tokenAuthenticationManager cannot be null");
	}

	@Test
	public void supportsWhenDPoPAuthenticationTokenThenReturnsTrue() {
		assertThat(this.authenticationProvider.supports(DPoPAuthenticationToken.class)).isTrue();
	}

	@Test
	public void setDPoPProofVerifierFactoryWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.authenticationProvider.setDPoPProofVerifierFactory(null))
			.withMessage("dPoPProofVerifierFactory cannot be null");
	}

	@Test
	public void authenticateWhenUnableToAuthenticateAccessTokenThenThrowOAuth2AuthenticationException() {
		DPoPAuthenticationToken dPoPAuthenticationToken = new DPoPAuthenticationToken("access-token", "dpop-proof",
				"GET", "https://resource1");
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(dPoPAuthenticationToken))
			.satisfies((ex) -> {
				assertThat(ex.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
				assertThat(ex.getError().getDescription())
					.isEqualTo("Unable to authenticate the DPoP-bound access token.");
			});
	}

	@Test
	public void authenticateWhenAthMissingThenThrowOAuth2AuthenticationException() {
		Jwt accessToken = generateAccessToken();
		JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(accessToken);
		given(this.tokenAuthenticationManager.authenticate(any())).willReturn(jwtAuthenticationToken);

		String method = "GET";
		String resourceUri = "https://resource1";

		// @formatter:off
		Map<String, Object> publicJwk = TestJwks.DEFAULT_RSA_JWK.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(Instant.now())
				.claim("htm", method)
				.claim("htu", resourceUri)
//				.claim("ath", computeSHA256(accessToken.getTokenValue()))
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		Jwt dPoPProof = this.dPoPProofJwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		DPoPAuthenticationToken dPoPAuthenticationToken = new DPoPAuthenticationToken(accessToken.getTokenValue(),
				dPoPProof.getTokenValue(), method, resourceUri);
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(dPoPAuthenticationToken))
			.satisfies((ex) -> {
				assertThat(ex.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_DPOP_PROOF);
				assertThat(ex.getMessage()).contains("ath claim is required");
			});
	}

	@Test
	public void authenticateWhenAthDoesNotMatchThenThrowOAuth2AuthenticationException() throws Exception {
		Jwt accessToken = generateAccessToken();
		JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(accessToken);
		given(this.tokenAuthenticationManager.authenticate(any())).willReturn(jwtAuthenticationToken);

		String method = "GET";
		String resourceUri = "https://resource1";

		// @formatter:off
		Map<String, Object> publicJwk = TestJwks.DEFAULT_RSA_JWK.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(Instant.now())
				.claim("htm", method)
				.claim("htu", resourceUri)
				.claim("ath", computeSHA256(accessToken.getTokenValue()) + "-mismatch")
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		Jwt dPoPProof = this.dPoPProofJwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		DPoPAuthenticationToken dPoPAuthenticationToken = new DPoPAuthenticationToken(accessToken.getTokenValue(),
				dPoPProof.getTokenValue(), method, resourceUri);
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(dPoPAuthenticationToken))
			.satisfies((ex) -> {
				assertThat(ex.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_DPOP_PROOF);
				assertThat(ex.getMessage()).contains("ath claim is invalid");
			});
	}

	@Test
	public void authenticateWhenJktMissingThenThrowOAuth2AuthenticationException() throws Exception {
		Jwt accessToken = generateAccessToken(null); // jkt claim is not added
		JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(accessToken);
		given(this.tokenAuthenticationManager.authenticate(any())).willReturn(jwtAuthenticationToken);

		String method = "GET";
		String resourceUri = "https://resource1";

		// @formatter:off
		Map<String, Object> publicJwk = TestJwks.DEFAULT_RSA_JWK.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(Instant.now())
				.claim("htm", method)
				.claim("htu", resourceUri)
				.claim("ath", computeSHA256(accessToken.getTokenValue()))
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		Jwt dPoPProof = this.dPoPProofJwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		DPoPAuthenticationToken dPoPAuthenticationToken = new DPoPAuthenticationToken(accessToken.getTokenValue(),
				dPoPProof.getTokenValue(), method, resourceUri);
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(dPoPAuthenticationToken))
			.satisfies((ex) -> {
				assertThat(ex.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_DPOP_PROOF);
				assertThat(ex.getMessage()).contains("jkt claim is required");
			});
	}

	@Test
	public void authenticateWhenJktDoesNotMatchThenThrowOAuth2AuthenticationException() throws Exception {
		// Use different jwk to make it not match
		Jwt accessToken = generateAccessToken(TestJwks.DEFAULT_EC_JWK);
		JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(accessToken);
		given(this.tokenAuthenticationManager.authenticate(any())).willReturn(jwtAuthenticationToken);

		String method = "GET";
		String resourceUri = "https://resource1";

		// @formatter:off
		Map<String, Object> publicJwk = TestJwks.DEFAULT_RSA_JWK.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(Instant.now())
				.claim("htm", method)
				.claim("htu", resourceUri)
				.claim("ath", computeSHA256(accessToken.getTokenValue()))
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		Jwt dPoPProof = this.dPoPProofJwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		DPoPAuthenticationToken dPoPAuthenticationToken = new DPoPAuthenticationToken(accessToken.getTokenValue(),
				dPoPProof.getTokenValue(), method, resourceUri);
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(dPoPAuthenticationToken))
			.satisfies((ex) -> {
				assertThat(ex.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_DPOP_PROOF);
				assertThat(ex.getMessage()).contains("jkt claim is invalid");
			});
	}

	@Test
	public void authenticateWhenDPoPProofValidThenSuccess() throws Exception {
		Jwt accessToken = generateAccessToken();
		JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(accessToken);
		given(this.tokenAuthenticationManager.authenticate(any())).willReturn(jwtAuthenticationToken);

		String method = "GET";
		String resourceUri = "https://resource1";

		// @formatter:off
		Map<String, Object> publicJwk = TestJwks.DEFAULT_RSA_JWK.toPublicJWK().toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(Instant.now())
				.claim("htm", method)
				.claim("htu", resourceUri)
				.claim("ath", computeSHA256(accessToken.getTokenValue()))
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		Jwt dPoPProof = this.dPoPProofJwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		DPoPAuthenticationToken dPoPAuthenticationToken = new DPoPAuthenticationToken(accessToken.getTokenValue(),
				dPoPProof.getTokenValue(), method, resourceUri);
		assertThat(this.authenticationProvider.authenticate(dPoPAuthenticationToken)).isSameAs(jwtAuthenticationToken);
	}

	private Jwt generateAccessToken() {
		return generateAccessToken(TestJwks.DEFAULT_RSA_JWK);
	}

	private Jwt generateAccessToken(JWK clientJwk) {
		Map<String, Object> jktClaim = null;
		if (clientJwk != null) {
			try {
				String sha256Thumbprint = clientJwk.toPublicJWK().computeThumbprint().toString();
				jktClaim = new HashMap<>();
				jktClaim.put("jkt", sha256Thumbprint);
			}
			catch (Exception ignored) {
			}
		}
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.ES256).build();
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(30, ChronoUnit.MINUTES);
		// @formatter:off
		JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder()
				.issuer("https://provider.com")
				.subject("subject")
				.issuedAt(issuedAt)
				.expiresAt(expiresAt)
				.id(UUID.randomUUID().toString());
		if (jktClaim != null) {
			claimsBuilder.claim("cnf", jktClaim);	// Bind client public key
		}
		// @formatter:on
		return this.accessTokenJwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claimsBuilder.build()));
	}

	private static String computeSHA256(String value) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(value.getBytes(StandardCharsets.UTF_8));
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
	}

}
