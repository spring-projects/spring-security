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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * A {@link JwtDecoderFactory factory} that provides a {@link JwtDecoder} for the
 * specified {@link DPoPProofContext} and is used for authenticating a DPoP Proof
 * {@link Jwt}.
 *
 * @author Joe Grandja
 * @since 6.5
 * @see JwtDecoderFactory
 * @see DPoPProofContext
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc9449">RFC 9449
 * OAuth 2.0 Demonstrating Proof of Possession (DPoP)</a>
 */
public final class DPoPProofJwtDecoderFactory implements JwtDecoderFactory<DPoPProofContext> {

	/**
	 * The default {@code OAuth2TokenValidator<Jwt>} factory that validates the
	 * {@code htm}, {@code htu}, {@code iat}, {@code jkt}, {@code ath} and {@code jti}
	 * claims of the DPoP Proof {@link Jwt}.
	 */
	public static final Function<DPoPProofContext, OAuth2TokenValidator<Jwt>> DEFAULT_JWT_VALIDATOR_FACTORY = createDefaultJwtValidatorFactory(
			Collections.emptyList());

	private static final JOSEObjectTypeVerifier<SecurityContext> DPOP_TYPE_VERIFIER = new DefaultJOSEObjectTypeVerifier<>(
			new JOSEObjectType("dpop+jwt"));

	private Function<DPoPProofContext, OAuth2TokenValidator<Jwt>> jwtValidatorFactory = DEFAULT_JWT_VALIDATOR_FACTORY;

	@Override
	public JwtDecoder createDecoder(DPoPProofContext dPoPProofContext) {
		Assert.notNull(dPoPProofContext, "dPoPProofContext cannot be null");
		NimbusJwtDecoder jwtDecoder = buildDecoder();
		jwtDecoder.setJwtValidator(this.jwtValidatorFactory.apply(dPoPProofContext));
		return jwtDecoder;
	}

	/**
	 * Sets the factory that provides an {@link OAuth2TokenValidator} for the specified
	 * {@link DPoPProofContext} and is used by the {@link JwtDecoder}. The default
	 * {@code OAuth2TokenValidator<Jwt>} factory is
	 * {@link #DEFAULT_JWT_VALIDATOR_FACTORY}.
	 * @param jwtValidatorFactory the factory that provides an
	 * {@link OAuth2TokenValidator} for the specified {@link DPoPProofContext}
	 */
	public void setJwtValidatorFactory(Function<DPoPProofContext, OAuth2TokenValidator<Jwt>> jwtValidatorFactory) {
		Assert.notNull(jwtValidatorFactory, "jwtValidatorFactory cannot be null");
		this.jwtValidatorFactory = jwtValidatorFactory;
	}

	/**
	 * Creates a factory that provides an {@link OAuth2TokenValidator} for the specified
	 * {@link DPoPProofContext} and is used by the {@link JwtDecoder}. The returned
	 * factory provides a validator that validates the {@code htm}, {@code htu},
	 * {@code iat}, {@code jkt}, {@code ath} and {@code jti} claims, along with any custom
	 * validators provided.
	 * @param validators the custom validators to add
	 * @return a factory that provides an {@link OAuth2TokenValidator} for the specified
	 * {@link DPoPProofContext}
	 * @since 6.5.12
	 */
	public static Function<DPoPProofContext, OAuth2TokenValidator<Jwt>> createDefaultJwtValidatorFactory(
			List<OAuth2TokenValidator<Jwt>> validators) {
		Assert.notNull(validators, "validators cannot be null");
		List<OAuth2TokenValidator<Jwt>> customValidators = new ArrayList<>();
		if (!CollectionUtils.isEmpty(validators)) {
			customValidators.addAll(validators);
		}
		final Duration clockSkew = Duration.ofSeconds(30);
		final JwtIssuedAtValidator jwtIssuedAtValidator;
		JwtIssuedAtValidator existingJwtIssuedAtValidator = CollectionUtils.findValueOfType(customValidators,
				JwtIssuedAtValidator.class);
		if (existingJwtIssuedAtValidator != null) {
			jwtIssuedAtValidator = existingJwtIssuedAtValidator;
			customValidators.remove(jwtIssuedAtValidator);
		}
		else {
			jwtIssuedAtValidator = new JwtIssuedAtValidator(true);
			jwtIssuedAtValidator.setClockSkew(clockSkew);
		}
		final DPoPProofReplayValidator dPoPProofReplayValidator;
		DPoPProofReplayValidator existingDPoPProofReplayValidator = CollectionUtils.findValueOfType(customValidators,
				DPoPProofReplayValidator.class);
		if (existingDPoPProofReplayValidator != null) {
			dPoPProofReplayValidator = existingDPoPProofReplayValidator;
			customValidators.remove(dPoPProofReplayValidator);
		}
		else {
			dPoPProofReplayValidator = new DPoPProofReplayValidator(new DPoPProofReplayValidator.InMemoryCache());
			dPoPProofReplayValidator.setClockSkew(clockSkew);
		}
		return (context) -> createDefaultJwtValidatorFactory(context, jwtIssuedAtValidator, dPoPProofReplayValidator,
				customValidators);
	}

	private static OAuth2TokenValidator<Jwt> createDefaultJwtValidatorFactory(DPoPProofContext context,
			JwtIssuedAtValidator jwtIssuedAtValidator, DPoPProofReplayValidator dPoPProofReplayValidator,
			List<OAuth2TokenValidator<Jwt>> customValidators) {
		// Add custom validators first then default validators in a specific order
		List<OAuth2TokenValidator<Jwt>> tokenValidators = new ArrayList<>();
		if (!CollectionUtils.isEmpty(customValidators)) {
			tokenValidators.addAll(customValidators);
		}
		tokenValidators.add(new JwtClaimValidator<>("htm", context.getMethod()::equalsIgnoreCase));
		tokenValidators.add(new JwtClaimValidator<>("htu", context.getTargetUri()::equals));
		tokenValidators.add(jwtIssuedAtValidator);
		if (context.getAccessToken() != null) {
			tokenValidators.add(new JwkThumbprintValidator(context.getAccessToken()));
			tokenValidators.add(new AthClaimValidator(context.getAccessToken()));
		}
		tokenValidators.add(dPoPProofReplayValidator);
		DelegatingOAuth2TokenValidator<Jwt> delegatingTokenValidator = new DelegatingOAuth2TokenValidator<>(
				tokenValidators);
		delegatingTokenValidator.setFailOnError(true);
		return delegatingTokenValidator;
	}

	private static NimbusJwtDecoder buildDecoder() {
		ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
		jwtProcessor.setJWSTypeVerifier(DPOP_TYPE_VERIFIER);
		jwtProcessor.setJWSKeySelector(jwsKeySelector());
		// Override the default Nimbus claims set verifier and use jwtValidatorFactory for
		// claims validation
		jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
		});
		return new NimbusJwtDecoder(jwtProcessor);
	}

	private static JWSKeySelector<SecurityContext> jwsKeySelector() {
		return (header, context) -> {
			JWSAlgorithm algorithm = header.getAlgorithm();
			if (!JWSAlgorithm.Family.RSA.contains(algorithm) && !JWSAlgorithm.Family.EC.contains(algorithm)) {
				throw new BadJwtException("Unsupported alg parameter in JWS Header: " + algorithm.getName());
			}

			JWK jwk = header.getJWK();
			if (jwk == null) {
				throw new BadJwtException("Missing jwk parameter in JWS Header.");
			}
			if (jwk.isPrivate()) {
				throw new BadJwtException("Invalid jwk parameter in JWS Header.");
			}

			try {
				if (JWSAlgorithm.Family.RSA.contains(algorithm) && jwk instanceof RSAKey rsaKey) {
					return Collections.singletonList(rsaKey.toRSAPublicKey());
				}
				else if (JWSAlgorithm.Family.EC.contains(algorithm) && jwk instanceof ECKey ecKey) {
					return Collections.singletonList(ecKey.toECPublicKey());
				}
			}
			catch (JOSEException ex) {
				throw new BadJwtException("Invalid jwk parameter in JWS Header.");
			}

			throw new BadJwtException("Invalid alg / jwk parameter in JWS Header: alg=" + algorithm.getName()
					+ ", jwk.kty=" + jwk.getKeyType().getValue());
		};
	}

	private static final class AthClaimValidator implements OAuth2TokenValidator<Jwt> {

		private final OAuth2Token accessToken;

		private AthClaimValidator(OAuth2Token accessToken) {
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

		private final OAuth2Token accessToken;

		private final ClaimAccessor claims;

		private JwkThumbprintValidator(OAuth2Token accessToken) {
			Assert.notNull(accessToken, "accessToken cannot be null");
			Assert.isInstanceOf(ClaimAccessor.class, accessToken, "accessToken must be instance of ClaimAccessor");
			this.accessToken = accessToken;
			this.claims = (ClaimAccessor) accessToken;
		}

		@Override
		public OAuth2TokenValidatorResult validate(Jwt jwt) {
			Assert.notNull(jwt, "DPoP proof jwt cannot be null");
			String jwkThumbprintClaim = null;
			Map<String, Object> confirmationMethodClaim = this.claims.getClaimAsMap("cnf");
			if (!CollectionUtils.isEmpty(confirmationMethodClaim) && confirmationMethodClaim.containsKey("jkt")) {
				jwkThumbprintClaim = (String) confirmationMethodClaim.get("jkt");
			}
			if (jwkThumbprintClaim == null) {
				OAuth2Error error = createOAuth2Error("jkt claim is required.");
				return OAuth2TokenValidatorResult.failure(error);
			}

			JWK jwk = null;
			@SuppressWarnings("unchecked")
			Map<String, Object> jwkJson = (Map<String, Object>) jwt.getHeaders().get("jwk");
			try {
				jwk = JWK.parse(jwkJson);
			}
			catch (Exception ignored) {
			}
			if (jwk == null) {
				OAuth2Error error = createOAuth2Error("jwk header is missing or invalid.");
				return OAuth2TokenValidatorResult.failure(error);
			}

			String jwkThumbprint;
			try {
				jwkThumbprint = jwk.computeThumbprint().toString();
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

	}

}
