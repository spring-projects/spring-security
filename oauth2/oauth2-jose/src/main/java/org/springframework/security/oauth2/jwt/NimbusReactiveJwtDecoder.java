/*
 * Copyright 2002-2019 the original author or authors.
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

import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;
import javax.crypto.SecretKey;

import com.nimbusds.jose.Header;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSecurityContextJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWKSecurityContext;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.util.Assert;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * An implementation of a {@link ReactiveJwtDecoder} that &quot;decodes&quot; a
 * JSON Web Token (JWT) and additionally verifies it's digital signature if the JWT is a
 * JSON Web Signature (JWS).
 *
 * <p>
 * <b>NOTE:</b> This implementation uses the Nimbus JOSE + JWT SDK internally.
 *
 * @author Rob Winch
 * @author Joe Grandja
 * @since 5.1
 * @see ReactiveJwtDecoder
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JSON Web Token (JWT)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515">JSON Web Signature (JWS)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7517">JSON Web Key (JWK)</a>
 * @see <a target="_blank" href="https://connect2id.com/products/nimbus-jose-jwt">Nimbus JOSE + JWT SDK</a>
 */
public final class NimbusReactiveJwtDecoder implements ReactiveJwtDecoder {
	private final Converter<JWT, Mono<JWTClaimsSet>> jwtProcessor;

	private OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators.createDefault();
	private Converter<Map<String, Object>, Map<String, Object>> claimSetConverter =
			MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());

	/**
	 * Constructs a {@code NimbusReactiveJwtDecoder} using the provided parameters.
	 *
	 * @param jwkSetUrl the JSON Web Key (JWK) Set {@code URL}
	 */
	public NimbusReactiveJwtDecoder(String jwkSetUrl) {
		this(withJwkSetUri(jwkSetUrl).processor());
	}

	/**
	 * Constructs a {@code NimbusReactiveJwtDecoder} using the provided parameters.
	 *
	 * @param publicKey the {@code RSAPublicKey} used to verify the signature
	 * @since 5.2
	 */
	public NimbusReactiveJwtDecoder(RSAPublicKey publicKey) {
		this(withPublicKey(publicKey).processor());
	}

	/**
	 * Constructs a {@code NimbusReactiveJwtDecoder} using the provided parameters.
	 *
	 * @param jwtProcessor the {@link Converter} used to process and verify the signed Jwt and return the Jwt Claim Set
	 * @since 5.2
	 */
	public NimbusReactiveJwtDecoder(Converter<JWT, Mono<JWTClaimsSet>> jwtProcessor) {
		this.jwtProcessor = jwtProcessor;
	}

	/**
	 * Use the provided {@link OAuth2TokenValidator} to validate incoming {@link Jwt}s.
	 *
	 * @param jwtValidator the {@link OAuth2TokenValidator} to use
	 */
	public void setJwtValidator(OAuth2TokenValidator<Jwt> jwtValidator) {
		Assert.notNull(jwtValidator, "jwtValidator cannot be null");
		this.jwtValidator = jwtValidator;
	}

	/**
	 * Use the following {@link Converter} for manipulating the JWT's claim set
	 *
	 * @param claimSetConverter the {@link Converter} to use
	 */
	public void setClaimSetConverter(Converter<Map<String, Object>, Map<String, Object>> claimSetConverter) {
		Assert.notNull(claimSetConverter, "claimSetConverter cannot be null");
		this.claimSetConverter = claimSetConverter;
	}

	@Override
	public Mono<Jwt> decode(String token) throws JwtException {
		JWT jwt = parse(token);
		if (jwt instanceof PlainJWT) {
			throw new JwtException("Unsupported algorithm of " + jwt.getHeader().getAlgorithm());
		}
		return this.decode(jwt);
	}

	private JWT parse(String token) {
		try {
			return JWTParser.parse(token);
		} catch (Exception ex) {
			throw new JwtException("An error occurred while attempting to decode the Jwt: " + ex.getMessage(), ex);
		}
	}

	private Mono<Jwt> decode(JWT parsedToken) {
		try {
			return this.jwtProcessor.convert(parsedToken)
				.map(set -> createJwt(parsedToken, set))
				.map(this::validateJwt)
				.onErrorMap(e -> !(e instanceof IllegalStateException) && !(e instanceof JwtException), e -> new JwtException("An error occurred while attempting to decode the Jwt: ", e));
		} catch (RuntimeException ex) {
			throw new JwtException("An error occurred while attempting to decode the Jwt: " + ex.getMessage(), ex);
		}
	}

	private Jwt createJwt(JWT parsedJwt, JWTClaimsSet jwtClaimsSet) {
		Map<String, Object> headers = new LinkedHashMap<>(parsedJwt.getHeader().toJSONObject());
		Map<String, Object> claims = this.claimSetConverter.convert(jwtClaimsSet.getClaims());

		Instant expiresAt = (Instant) claims.get(JwtClaimNames.EXP);
		Instant issuedAt = (Instant) claims.get(JwtClaimNames.IAT);
		return new Jwt(parsedJwt.getParsedString(), issuedAt, expiresAt, headers, claims);
	}

	private Jwt validateJwt(Jwt jwt) {
		OAuth2TokenValidatorResult result = this.jwtValidator.validate(jwt);

		if ( result.hasErrors() ) {
			String message = result.getErrors().iterator().next().getDescription();
			throw new JwtValidationException(message, result.getErrors());
		}

		return jwt;
	}

	/**
	 * Use the given
	 * <a href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</a> uri to validate JWTs.
	 *
	 * @param jwkSetUri the JWK Set uri to use
	 * @return a {@link JwkSetUriReactiveJwtDecoderBuilder} for further configurations
	 *
	 * @since 5.2
	 */
	public static JwkSetUriReactiveJwtDecoderBuilder withJwkSetUri(String jwkSetUri) {
		return new JwkSetUriReactiveJwtDecoderBuilder(jwkSetUri);
	}

	/**
	 * Use the given public key to validate JWTs
	 *
	 * @param key the public key to use
	 * @return a {@link PublicKeyReactiveJwtDecoderBuilder} for further configurations
	 *
	 * @since 5.2
	 */
	public static PublicKeyReactiveJwtDecoderBuilder withPublicKey(RSAPublicKey key) {
		return new PublicKeyReactiveJwtDecoderBuilder(key);
	}

	/**
	 * Use the given {@code SecretKey} to validate the MAC on a JSON Web Signature (JWS).
	 *
	 * @param secretKey the {@code SecretKey} used to validate the MAC
	 * @return a {@link SecretKeyReactiveJwtDecoderBuilder} for further configurations
	 *
	 * @since 5.2
	 */
	public static SecretKeyReactiveJwtDecoderBuilder withSecretKey(SecretKey secretKey) {
		return new SecretKeyReactiveJwtDecoderBuilder(secretKey);
	}

	/**
	 * Use the given {@link Function} to validate JWTs
	 *
	 * @param source the {@link Function}
	 * @return a {@link JwkSourceReactiveJwtDecoderBuilder} for further configurations
	 *
	 * @since 5.2
	 */
	public static JwkSourceReactiveJwtDecoderBuilder withJwkSource(Function<SignedJWT, Flux<JWK>> source) {
		return new JwkSourceReactiveJwtDecoderBuilder(source);
	}

	/**
	 * A builder for creating {@link NimbusReactiveJwtDecoder} instances based on a
	 * <a target="_blank" href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</a> uri.
	 *
	 * @since 5.2
	 */
	public static final class JwkSetUriReactiveJwtDecoderBuilder {
		private final String jwkSetUri;
		private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.RS256;
		private WebClient webClient = WebClient.create();

		private JwkSetUriReactiveJwtDecoderBuilder(String jwkSetUri) {
			Assert.hasText(jwkSetUri, "jwkSetUri cannot be empty");
			this.jwkSetUri = jwkSetUri;
		}

		/**
		 * Use the given signing
		 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target="_blank">algorithm</a>.
		 *
		 * @param signatureAlgorithm the algorithm to use
		 * @return a {@link JwkSetUriReactiveJwtDecoderBuilder} for further configurations
		 */
		public JwkSetUriReactiveJwtDecoderBuilder jwsAlgorithm(SignatureAlgorithm signatureAlgorithm) {
			Assert.notNull(signatureAlgorithm, "sig cannot be null");
			this.jwsAlgorithm = JWSAlgorithm.parse(signatureAlgorithm.getName());
			return this;
		}

		/**
		 * Use the given {@link WebClient} to coordinate with the authorization servers indicated in the
		 * <a href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</a> uri
		 * as well as the
		 * <a href="https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a>.
		 *
		 * @param webClient
		 * @return a {@link JwkSetUriReactiveJwtDecoderBuilder} for further configurations
		 */
		public JwkSetUriReactiveJwtDecoderBuilder webClient(WebClient webClient) {
			Assert.notNull(webClient, "webClient cannot be null");
			this.webClient = webClient;
			return this;
		}

		/**
		 * Build the configured {@link NimbusReactiveJwtDecoder}.
		 *
		 * @return the configured {@link NimbusReactiveJwtDecoder}
		 */
		public NimbusReactiveJwtDecoder build() {
			return new NimbusReactiveJwtDecoder(processor());
		}

		Converter<JWT, Mono<JWTClaimsSet>> processor() {
			JWKSecurityContextJWKSet jwkSource = new JWKSecurityContextJWKSet();

			JWSKeySelector<JWKSecurityContext> jwsKeySelector =
					new JWSVerificationKeySelector<>(this.jwsAlgorithm, jwkSource);
			DefaultJWTProcessor<JWKSecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
			jwtProcessor.setJWSKeySelector(jwsKeySelector);
			jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {});

			ReactiveRemoteJWKSource source = new ReactiveRemoteJWKSource(this.jwkSetUri);
			source.setWebClient(this.webClient);

			return jwt -> {
				JWKSelector selector = createSelector(jwt.getHeader());
				return source.get(selector)
						.onErrorMap(e -> new IllegalStateException("Could not obtain the keys", e))
						.map(jwkList -> createClaimsSet(jwtProcessor, jwt, new JWKSecurityContext(jwkList)));
			};
		}

		private JWKSelector createSelector(Header header) {
			if (!this.jwsAlgorithm.equals(header.getAlgorithm())) {
				throw new JwtException("Unsupported algorithm of " + header.getAlgorithm());
			}

			return new JWKSelector(JWKMatcher.forJWSHeader((JWSHeader) header));
		}
	}

	/**
	 * A builder for creating {@link NimbusReactiveJwtDecoder} instances based on a public key.
	 *
	 * @since 5.2
	 */
	public static final class PublicKeyReactiveJwtDecoderBuilder {
		private final RSAPublicKey key;
		private JWSAlgorithm jwsAlgorithm;

		private PublicKeyReactiveJwtDecoderBuilder(RSAPublicKey key) {
			Assert.notNull(key, "key cannot be null");
			this.key = key;
			this.jwsAlgorithm = JWSAlgorithm.RS256;
		}

		/**
		 * Use the given signing
		 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target="_blank">algorithm</a>.
		 * The value should be one of
		 * <a href="https://tools.ietf.org/html/rfc7518#section-3.3" target="_blank">RS256, RS384, or RS512</a>.
		 *
		 * @param signatureAlgorithm the algorithm to use
		 * @return a {@link PublicKeyReactiveJwtDecoderBuilder} for further configurations
		 */
		public PublicKeyReactiveJwtDecoderBuilder signatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
			Assert.notNull(signatureAlgorithm, "signatureAlgorithm cannot be null");
			this.jwsAlgorithm = JWSAlgorithm.parse(signatureAlgorithm.getName());
			return this;
		}

		/**
		 * Build the configured {@link NimbusReactiveJwtDecoder}.
		 *
		 * @return the configured {@link NimbusReactiveJwtDecoder}
		 */
		public NimbusReactiveJwtDecoder build() {
			return new NimbusReactiveJwtDecoder(processor());
		}

		Converter<JWT, Mono<JWTClaimsSet>> processor() {
			if (!JWSAlgorithm.Family.RSA.contains(this.jwsAlgorithm)) {
				throw new IllegalStateException("The provided key is of type RSA; " +
						"however the signature algorithm is of some other type: " +
						this.jwsAlgorithm + ". Please indicate one of RS256, RS384, or RS512.");
			}

			JWSKeySelector<SecurityContext> jwsKeySelector =
					new SingleKeyJWSKeySelector<>(this.jwsAlgorithm, this.key);
			DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
			jwtProcessor.setJWSKeySelector(jwsKeySelector);

			// Spring Security validates the claim set independent from Nimbus
			jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> { });

			return jwt -> Mono.just(createClaimsSet(jwtProcessor, jwt, null));
		}
	}

	/**
	 * A builder for creating {@link NimbusReactiveJwtDecoder} instances based on a {@code SecretKey}.
	 *
	 * @since 5.2
	 */
	public static final class SecretKeyReactiveJwtDecoderBuilder {
		private final SecretKey secretKey;
		private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS256;

		private SecretKeyReactiveJwtDecoderBuilder(SecretKey secretKey) {
			Assert.notNull(secretKey, "secretKey cannot be null");
			this.secretKey = secretKey;
		}

		/**
		 * Use the given
		 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target="_blank">algorithm</a>
		 * when generating the MAC.
		 *
		 * The value should be one of
		 * <a href="https://tools.ietf.org/html/rfc7518#section-3.2" target="_blank">HS256, HS384 or HS512</a>.
		 *
		 * @param macAlgorithm the MAC algorithm to use
		 * @return a {@link SecretKeyReactiveJwtDecoderBuilder} for further configurations
		 */
		public SecretKeyReactiveJwtDecoderBuilder macAlgorithm(MacAlgorithm macAlgorithm) {
			Assert.notNull(macAlgorithm, "macAlgorithm cannot be null");
			this.jwsAlgorithm = JWSAlgorithm.parse(macAlgorithm.getName());
			return this;
		}

		/**
		 * Build the configured {@link NimbusReactiveJwtDecoder}.
		 *
		 * @return the configured {@link NimbusReactiveJwtDecoder}
		 */
		public NimbusReactiveJwtDecoder build() {
			return new NimbusReactiveJwtDecoder(processor());
		}

		Converter<JWT, Mono<JWTClaimsSet>> processor() {
			JWSKeySelector<SecurityContext> jwsKeySelector =
					new SingleKeyJWSKeySelector<>(this.jwsAlgorithm, this.secretKey);
			DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
			jwtProcessor.setJWSKeySelector(jwsKeySelector);

			// Spring Security validates the claim set independent from Nimbus
			jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> { });

			return jwt -> Mono.just(createClaimsSet(jwtProcessor, jwt, null));
		}
	}

	/**
	 * A builder for creating {@link NimbusReactiveJwtDecoder} instances.
	 *
	 * @since 5.2
	 */
	public static final class JwkSourceReactiveJwtDecoderBuilder {
		private final Function<SignedJWT, Flux<JWK>> jwkSource;
		private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.RS256;

		private JwkSourceReactiveJwtDecoderBuilder(Function<SignedJWT, Flux<JWK>> jwkSource) {
			Assert.notNull(jwkSource, "jwkSource cannot be null");
			this.jwkSource = jwkSource;
		}

		/**
		 * Use the given signing
		 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target="_blank">algorithm</a>.
		 *
		 * @param jwsAlgorithm the algorithm to use
		 * @return a {@link JwkSourceReactiveJwtDecoderBuilder} for further configurations
		 */
		public JwkSourceReactiveJwtDecoderBuilder jwsAlgorithm(JwsAlgorithm jwsAlgorithm) {
			Assert.notNull(jwsAlgorithm, "jwsAlgorithm cannot be null");
			this.jwsAlgorithm = JWSAlgorithm.parse(jwsAlgorithm.getName());
			return this;
		}

		/**
		 * Build the configured {@link NimbusReactiveJwtDecoder}.
		 *
		 * @return the configured {@link NimbusReactiveJwtDecoder}
		 */
		public NimbusReactiveJwtDecoder build() {
			return new NimbusReactiveJwtDecoder(processor());
		}

		Converter<JWT, Mono<JWTClaimsSet>> processor() {
			JWKSecurityContextJWKSet jwkSource = new JWKSecurityContextJWKSet();
			JWSKeySelector<JWKSecurityContext> jwsKeySelector =
					new JWSVerificationKeySelector<>(this.jwsAlgorithm, jwkSource);
			DefaultJWTProcessor<JWKSecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
			jwtProcessor.setJWSKeySelector(jwsKeySelector);
			jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {});

			return jwt -> {
				if (jwt instanceof SignedJWT) {
					return this.jwkSource.apply((SignedJWT) jwt)
							.onErrorMap(e -> new IllegalStateException("Could not obtain the keys", e))
							.collectList()
							.map(jwks -> createClaimsSet(jwtProcessor, jwt, new JWKSecurityContext(jwks)));
				}
				throw new JwtException("Unsupported algorithm of " + jwt.getHeader().getAlgorithm());
			};
		}
	}

	private static <C extends SecurityContext> JWTClaimsSet createClaimsSet(JWTProcessor<C> jwtProcessor,
																			JWT parsedToken, C context) {
		try {
			return jwtProcessor.process(parsedToken, context);
		}
		catch (BadJOSEException | JOSEException e) {
			throw new JwtException("Failed to validate the token", e);
		}
	}
}
