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

package org.springframework.security.oauth2.jwt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
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

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.util.Assert;
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
	 * {@code htm}, {@code htu}, {@code jti} and {@code iat} claims of the DPoP Proof
	 * {@link Jwt}.
	 */
	public static final Function<DPoPProofContext, OAuth2TokenValidator<Jwt>> DEFAULT_JWT_VALIDATOR_FACTORY = defaultJwtValidatorFactory();

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

	private static Function<DPoPProofContext, OAuth2TokenValidator<Jwt>> defaultJwtValidatorFactory() {
		return (context) -> new DelegatingOAuth2TokenValidator<>(
				new JwtClaimValidator<>("htm", context.getMethod()::equals),
				new JwtClaimValidator<>("htu", context.getTargetUri()::equals), new JtiClaimValidator(),
				new JwtIssuedAtValidator(true));
	}

	private static final class JtiClaimValidator implements OAuth2TokenValidator<Jwt> {

		private static final Map<String, Long> JTI_CACHE = Collections.synchronizedMap(new JtiCache());

		@Override
		public OAuth2TokenValidatorResult validate(Jwt jwt) {
			Assert.notNull(jwt, "DPoP proof jwt cannot be null");
			String jti = jwt.getId();
			if (!StringUtils.hasText(jti)) {
				OAuth2Error error = createOAuth2Error("jti claim is required.");
				return OAuth2TokenValidatorResult.failure(error);
			}

			// Enforce single-use to protect against DPoP proof replay
			String jtiHash;
			try {
				jtiHash = computeSHA256(jti);
			}
			catch (Exception ex) {
				OAuth2Error error = createOAuth2Error("jti claim is invalid.");
				return OAuth2TokenValidatorResult.failure(error);
			}
			Instant expiry = Instant.now().plus(1, ChronoUnit.HOURS);
			if ((JTI_CACHE.putIfAbsent(jtiHash, expiry.toEpochMilli())) != null) {
				// Already used
				OAuth2Error error = createOAuth2Error("jti claim is invalid.");
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

		private static final class JtiCache extends LinkedHashMap<String, Long> {

			private static final int MAX_SIZE = 1000;

			@Override
			protected boolean removeEldestEntry(Map.Entry<String, Long> eldest) {
				if (size() > MAX_SIZE) {
					return true;
				}
				Instant expiry = Instant.ofEpochMilli(eldest.getValue());
				return Instant.now().isAfter(expiry);
			}

		}

	}

}
