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
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.function.Function;

import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.DPoPProofContext;
import org.springframework.security.oauth2.jwt.DPoPProofJwtDecoderFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * @author Joe Grandja
 * @since 6.5
 * @see DPoPAuthenticationToken
 * @see DPoPProofJwtDecoderFactory
 */
public final class DPoPAuthenticationProvider implements AuthenticationProvider {

	private final AuthenticationManager tokenAuthenticationManager;

	private JwtDecoderFactory<DPoPProofContext> dPoPProofVerifierFactory;

	public DPoPAuthenticationProvider(AuthenticationManager tokenAuthenticationManager) {
		Assert.notNull(tokenAuthenticationManager, "tokenAuthenticationManager cannot be null");
		this.tokenAuthenticationManager = tokenAuthenticationManager;
		Function<DPoPProofContext, OAuth2TokenValidator<Jwt>> jwtValidatorFactory = (
				context) -> new DelegatingOAuth2TokenValidator<>(
						// Use default validators
						DPoPProofJwtDecoderFactory.DEFAULT_JWT_VALIDATOR_FACTORY.apply(context),
						// Add custom validators
						new AthClaimValidator(context.getAccessToken()),
						new JwkThumbprintValidator(context.getAccessToken()));
		DPoPProofJwtDecoderFactory dPoPProofJwtDecoderFactory = new DPoPProofJwtDecoderFactory();
		dPoPProofJwtDecoderFactory.setJwtValidatorFactory(jwtValidatorFactory);
		this.dPoPProofVerifierFactory = dPoPProofJwtDecoderFactory;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		DPoPAuthenticationToken dPoPAuthenticationToken = (DPoPAuthenticationToken) authentication;

		BearerTokenAuthenticationToken accessTokenAuthenticationRequest = new BearerTokenAuthenticationToken(
				dPoPAuthenticationToken.getAccessToken());
		Authentication accessTokenAuthenticationResult = this.tokenAuthenticationManager
			.authenticate(accessTokenAuthenticationRequest);

		AbstractOAuth2TokenAuthenticationToken<OAuth2Token> accessTokenAuthentication = null;
		if (accessTokenAuthenticationResult instanceof AbstractOAuth2TokenAuthenticationToken) {
			accessTokenAuthentication = (AbstractOAuth2TokenAuthenticationToken) accessTokenAuthenticationResult;
		}
		if (accessTokenAuthentication == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
					"Unable to authenticate the DPoP-bound access token.", null);
			throw new OAuth2AuthenticationException(error);
		}

		OAuth2AccessTokenClaims accessToken = new OAuth2AccessTokenClaims(accessTokenAuthentication.getToken(),
				accessTokenAuthentication.getTokenAttributes());

		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPAuthenticationToken.getDPoPProof())
			.accessToken(accessToken)
			.method(dPoPAuthenticationToken.getMethod())
			.targetUri(dPoPAuthenticationToken.getResourceUri())
			.build();
		JwtDecoder dPoPProofVerifier = this.dPoPProofVerifierFactory.createDecoder(dPoPProofContext);

		try {
			dPoPProofVerifier.decode(dPoPProofContext.getDPoPProof());
		}
		catch (JwtException ex) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_DPOP_PROOF);
			throw new OAuth2AuthenticationException(error, ex);
		}

		return accessTokenAuthenticationResult;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return DPoPAuthenticationToken.class.isAssignableFrom(authentication);
	}

	public void setDPoPProofVerifierFactory(JwtDecoderFactory<DPoPProofContext> dPoPProofVerifierFactory) {
		Assert.notNull(dPoPProofVerifierFactory, "dPoPProofVerifierFactory cannot be null");
		this.dPoPProofVerifierFactory = dPoPProofVerifierFactory;
	}

	private static final class AthClaimValidator implements OAuth2TokenValidator<Jwt> {

		private final OAuth2AccessTokenClaims accessToken;

		private AthClaimValidator(OAuth2AccessTokenClaims accessToken) {
			Assert.notNull(accessToken, "accessToken cannot be null");
			this.accessToken = accessToken;
		}

		@Override
		public OAuth2TokenValidatorResult validate(Jwt jwt) {
			Assert.notNull(jwt, "DPoP proof jwt cannot be null");
			String accessTokenHashClaim = jwt.getClaimAsString("ath");
			if (!StringUtils.hasText(accessTokenHashClaim)) {
				OAuth2Error error = createOAuth2Error("ath claim is required.");
				return OAuth2TokenValidatorResult.failure(error);
			}

			String accessTokenHash;
			try {
				accessTokenHash = computeSHA256(this.accessToken.getTokenValue());
			}
			catch (Exception ex) {
				OAuth2Error error = createOAuth2Error("Failed to compute SHA-256 Thumbprint for access token.");
				return OAuth2TokenValidatorResult.failure(error);
			}
			if (!accessTokenHashClaim.equals(accessTokenHash)) {
				OAuth2Error error = createOAuth2Error("ath claim is invalid.");
				return OAuth2TokenValidatorResult.failure(error);
			}
			return OAuth2TokenValidatorResult.success();
		}

		private static OAuth2Error createOAuth2Error(String reason) {
			return new OAuth2Error(OAuth2ErrorCodes.INVALID_DPOP_PROOF, reason, null);
		}

		private static String computeSHA256(String value) throws Exception {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] digest = md.digest(value.getBytes(StandardCharsets.UTF_8));
			return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
		}

	}

	private static final class JwkThumbprintValidator implements OAuth2TokenValidator<Jwt> {

		private final OAuth2AccessTokenClaims accessToken;

		private JwkThumbprintValidator(OAuth2AccessTokenClaims accessToken) {
			Assert.notNull(accessToken, "accessToken cannot be null");
			this.accessToken = accessToken;
		}

		@Override
		public OAuth2TokenValidatorResult validate(Jwt jwt) {
			Assert.notNull(jwt, "DPoP proof jwt cannot be null");
			String jwkThumbprintClaim = null;
			Map<String, Object> confirmationMethodClaim = this.accessToken.getClaimAsMap("cnf");
			if (!CollectionUtils.isEmpty(confirmationMethodClaim) && confirmationMethodClaim.containsKey("jkt")) {
				jwkThumbprintClaim = (String) confirmationMethodClaim.get("jkt");
			}
			if (jwkThumbprintClaim == null) {
				OAuth2Error error = createOAuth2Error("jkt claim is required.");
				return OAuth2TokenValidatorResult.failure(error);
			}

			PublicKey publicKey = null;
			@SuppressWarnings("unchecked")
			Map<String, Object> jwkJson = (Map<String, Object>) jwt.getHeaders().get("jwk");
			try {
				JWK jwk = JWK.parse(jwkJson);
				if (jwk instanceof AsymmetricJWK) {
					publicKey = ((AsymmetricJWK) jwk).toPublicKey();
				}
			}
			catch (Exception ignored) {
			}
			if (publicKey == null) {
				OAuth2Error error = createOAuth2Error("jwk header is missing or invalid.");
				return OAuth2TokenValidatorResult.failure(error);
			}

			String jwkThumbprint;
			try {
				jwkThumbprint = computeSHA256(publicKey);
			}
			catch (Exception ex) {
				OAuth2Error error = createOAuth2Error("Failed to compute SHA-256 Thumbprint for jwk.");
				return OAuth2TokenValidatorResult.failure(error);
			}

			if (!jwkThumbprintClaim.equals(jwkThumbprint)) {
				OAuth2Error error = createOAuth2Error("jkt claim is invalid.");
				return OAuth2TokenValidatorResult.failure(error);
			}
			return OAuth2TokenValidatorResult.success();
		}

		private static OAuth2Error createOAuth2Error(String reason) {
			return new OAuth2Error(OAuth2ErrorCodes.INVALID_DPOP_PROOF, reason, null);
		}

		private static String computeSHA256(PublicKey publicKey) throws Exception {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] digest = md.digest(publicKey.getEncoded());
			return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
		}

	}

	private static final class OAuth2AccessTokenClaims implements OAuth2Token, ClaimAccessor {

		private final OAuth2Token accessToken;

		private final Map<String, Object> claims;

		private OAuth2AccessTokenClaims(OAuth2Token accessToken, Map<String, Object> claims) {
			this.accessToken = accessToken;
			this.claims = claims;
		}

		@Override
		public String getTokenValue() {
			return this.accessToken.getTokenValue();
		}

		@Override
		public Instant getIssuedAt() {
			return this.accessToken.getIssuedAt();
		}

		@Override
		public Instant getExpiresAt() {
			return this.accessToken.getExpiresAt();
		}

		@Override
		public Map<String, Object> getClaims() {
			return this.claims;
		}

	}

}
