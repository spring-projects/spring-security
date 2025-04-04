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

import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;

import javax.crypto.SecretKey;

import com.nimbusds.jose.Header;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSecurityContextJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWKSecurityContext;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.proc.SingleKeyJWSKeySelector;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuple2;
import reactor.util.function.Tuples;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * An implementation of a {@link ReactiveJwtDecoder} that &quot;decodes&quot; a JSON Web
 * Token (JWT) and additionally verifies its digital signature if the JWT is a JSON Web
 * Signature (JWS).
 *
 * <p>
 * <b>NOTE:</b> This implementation uses the Nimbus JOSE + JWT SDK internally.
 *
 * @author Rob Winch
 * @author Joe Grandja
 * @since 5.1
 * @see ReactiveJwtDecoder
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JSON Web Token
 * (JWT)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515">JSON Web Signature
 * (JWS)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7517">JSON Web Key
 * (JWK)</a>
 * @see <a target="_blank" href="https://connect2id.com/products/nimbus-jose-jwt">Nimbus
 * JOSE + JWT SDK</a>
 */
public final class NimbusReactiveJwtDecoder implements ReactiveJwtDecoder {

	private final Converter<JWT, Mono<JWTClaimsSet>> jwtProcessor;

	private OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators.createDefault();

	private Converter<Map<String, Object>, Map<String, Object>> claimSetConverter = MappedJwtClaimSetConverter
		.withDefaults(Collections.emptyMap());

	/**
	 * Constructs a {@code NimbusReactiveJwtDecoder} using the provided parameters.
	 * @param jwkSetUrl the JSON Web Key (JWK) Set {@code URL}
	 */
	public NimbusReactiveJwtDecoder(String jwkSetUrl) {
		this(withJwkSetUri(jwkSetUrl).processor());
	}

	/**
	 * Constructs a {@code NimbusReactiveJwtDecoder} using the provided parameters.
	 * @param publicKey the {@code RSAPublicKey} used to verify the signature
	 * @since 5.2
	 */
	public NimbusReactiveJwtDecoder(RSAPublicKey publicKey) {
		this(withPublicKey(publicKey).processor());
	}

	/**
	 * Constructs a {@code NimbusReactiveJwtDecoder} using the provided parameters.
	 * @param jwtProcessor the {@link Converter} used to process and verify the signed Jwt
	 * and return the Jwt Claim Set
	 * @since 5.2
	 */
	public NimbusReactiveJwtDecoder(Converter<JWT, Mono<JWTClaimsSet>> jwtProcessor) {
		this.jwtProcessor = jwtProcessor;
	}

	/**
	 * Use the provided {@link OAuth2TokenValidator} to validate incoming {@link Jwt}s.
	 * @param jwtValidator the {@link OAuth2TokenValidator} to use
	 */
	public void setJwtValidator(OAuth2TokenValidator<Jwt> jwtValidator) {
		Assert.notNull(jwtValidator, "jwtValidator cannot be null");
		this.jwtValidator = jwtValidator;
	}

	/**
	 * Use the following {@link Converter} for manipulating the JWT's claim set
	 * @param claimSetConverter the {@link Converter} to use
	 */
	public void setClaimSetConverter(Converter<Map<String, Object>, Map<String, Object>> claimSetConverter) {
		Assert.notNull(claimSetConverter, "claimSetConverter cannot be null");
		this.claimSetConverter = claimSetConverter;
	}

	@Override
	public Mono<Jwt> decode(String token) {
		try {
			JWT jwt = JWTParser.parse(token);
			if (jwt instanceof PlainJWT) {
				return Mono.error(new BadJwtException("Unsupported algorithm of " + jwt.getHeader().getAlgorithm()));
			}
			return this.decode(jwt);
		}
		catch (Exception ex) {
			return Mono.error(new BadJwtException(
					"An error occurred while attempting to decode the Jwt: " + ex.getMessage(), ex));
		}
	}

	private Mono<Jwt> decode(JWT parsedToken) {
		try {
			// @formatter:off
			return this.jwtProcessor.convert(parsedToken)
					.map((set) -> createJwt(parsedToken, set))
					.map(this::validateJwt)
					.onErrorMap((ex) -> !(ex instanceof IllegalStateException) && !(ex instanceof JwtException),
							(ex) -> new JwtException("An error occurred while attempting to decode the Jwt: ", ex));
			// @formatter:on
		}
		catch (JwtException ex) {
			throw ex;
		}
		catch (RuntimeException ex) {
			throw new JwtException("An error occurred while attempting to decode the Jwt: " + ex.getMessage(), ex);
		}
	}

	private Jwt createJwt(JWT parsedJwt, JWTClaimsSet jwtClaimsSet) {
		try {
			Map<String, Object> headers = new LinkedHashMap<>(parsedJwt.getHeader().toJSONObject());
			Map<String, Object> claims = this.claimSetConverter.convert(jwtClaimsSet.getClaims());
			return Jwt.withTokenValue(parsedJwt.getParsedString())
				.headers((h) -> h.putAll(headers))
				.claims((c) -> c.putAll(claims))
				.build();
		}
		catch (Exception ex) {
			throw new BadJwtException("An error occurred while attempting to decode the Jwt: " + ex.getMessage(), ex);
		}
	}

	private Jwt validateJwt(Jwt jwt) {
		OAuth2TokenValidatorResult result = this.jwtValidator.validate(jwt);
		if (result.hasErrors()) {
			Collection<OAuth2Error> errors = result.getErrors();
			String validationErrorString = getJwtValidationExceptionMessage(errors);
			throw new JwtValidationException(validationErrorString, errors);
		}
		return jwt;
	}

	private String getJwtValidationExceptionMessage(Collection<OAuth2Error> errors) {
		for (OAuth2Error oAuth2Error : errors) {
			if (StringUtils.hasLength(oAuth2Error.getDescription())) {
				return oAuth2Error.getDescription();
			}
		}
		return "Unable to validate Jwt";
	}

	/**
	 * Use the given <a href=
	 * "https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a>
	 * by making an <a href=
	 * "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">OpenID
	 * Provider Configuration Request</a> and using the values in the <a href=
	 * "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse">OpenID
	 * Provider Configuration Response</a> to derive the needed
	 * <a href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</a> uri.
	 * @param issuer the <a href=
	 * "https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a>
	 * @return a {@link NimbusJwtDecoder.JwkSetUriJwtDecoderBuilder} that will derive the
	 * JWK Set uri when {@link NimbusJwtDecoder.JwkSetUriJwtDecoderBuilder#build} is
	 * called
	 * @since 6.1
	 * @see JwtDecoders
	 */
	public static JwkSetUriReactiveJwtDecoderBuilder withIssuerLocation(String issuer) {
		return new JwkSetUriReactiveJwtDecoderBuilder(
				(web) -> ReactiveJwtDecoderProviderConfigurationUtils.getConfigurationForIssuerLocation(issuer, web)
					.flatMap((configuration) -> {
						try {
							JwtDecoderProviderConfigurationUtils.validateIssuer(configuration, issuer);
						}
						catch (IllegalStateException ex) {
							return Mono.error(ex);
						}
						return Mono.just(configuration.get("jwks_uri").toString());
					}),
				ReactiveJwtDecoderProviderConfigurationUtils::getJWSAlgorithms);
	}

	/**
	 * Use the given <a href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</a>
	 * uri to validate JWTs.
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
	 * @param source the {@link Function}
	 * @return a {@link JwkSourceReactiveJwtDecoderBuilder} for further configurations
	 *
	 * @since 5.2
	 */
	public static JwkSourceReactiveJwtDecoderBuilder withJwkSource(Function<SignedJWT, Flux<JWK>> source) {
		return new JwkSourceReactiveJwtDecoderBuilder(source);
	}

	private static <C extends SecurityContext> JWTClaimsSet createClaimsSet(JWTProcessor<C> jwtProcessor,
			JWT parsedToken, C context) {
		try {
			return jwtProcessor.process(parsedToken, context);
		}
		catch (BadJOSEException ex) {
			throw new BadJwtException("Failed to validate the token", ex);
		}
		catch (JOSEException ex) {
			throw new JwtException("Failed to validate the token", ex);
		}
	}

	/**
	 * A builder for creating {@link NimbusReactiveJwtDecoder} instances based on a
	 * <a target="_blank" href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</a>
	 * uri.
	 *
	 * @since 5.2
	 */
	public static final class JwkSetUriReactiveJwtDecoderBuilder {

		private static final JOSEObjectTypeVerifier<JWKSecurityContext> JWT_TYPE_VERIFIER = new DefaultJOSEObjectTypeVerifier<>(
				JOSEObjectType.JWT, null);

		private static final JOSEObjectTypeVerifier<JWKSecurityContext> NO_TYPE_VERIFIER = (header, context) -> {
		};

		private static final Duration FOREVER = Duration.ofMillis(Long.MAX_VALUE);

		private Function<WebClient, Mono<String>> jwkSetUri;

		private Function<ReactiveRemoteJWKSource, Mono<Set<JWSAlgorithm>>> defaultAlgorithms = (source) -> Mono
			.just(Set.of(JWSAlgorithm.RS256));

		private JOSEObjectTypeVerifier<JWKSecurityContext> typeVerifier = JWT_TYPE_VERIFIER;

		private Set<SignatureAlgorithm> signatureAlgorithms = new HashSet<>();

		private WebClient webClient = WebClient.create();

		private BiFunction<ReactiveRemoteJWKSource, ConfigurableJWTProcessor<JWKSecurityContext>, Mono<ConfigurableJWTProcessor<JWKSecurityContext>>> jwtProcessorCustomizer;

		private JwkSetUriReactiveJwtDecoderBuilder(String jwkSetUri) {
			Assert.hasText(jwkSetUri, "jwkSetUri cannot be empty");
			this.jwkSetUri = (web) -> Mono.just(jwkSetUri);
			this.jwtProcessorCustomizer = (source, processor) -> Mono.just(processor);
		}

		private JwkSetUriReactiveJwtDecoderBuilder(Function<WebClient, Mono<String>> jwkSetUri,
				Function<ReactiveRemoteJWKSource, Mono<Set<JWSAlgorithm>>> defaultAlgorithms) {
			Assert.notNull(jwkSetUri, "jwkSetUri cannot be null");
			Assert.notNull(defaultAlgorithms, "defaultAlgorithms cannot be null");
			this.jwkSetUri = jwkSetUri;
			this.defaultAlgorithms = defaultAlgorithms;
			this.jwtProcessorCustomizer = (source, processor) -> Mono.just(processor);
		}

		/**
		 * Append the given signing
		 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target=
		 * "_blank">algorithm</a> to the set of algorithms to use.
		 * @param signatureAlgorithm the algorithm to use
		 * @return a {@link JwkSetUriReactiveJwtDecoderBuilder} for further configurations
		 */
		public JwkSetUriReactiveJwtDecoderBuilder jwsAlgorithm(SignatureAlgorithm signatureAlgorithm) {
			Assert.notNull(signatureAlgorithm, "sig cannot be null");
			this.signatureAlgorithms.add(signatureAlgorithm);
			return this;
		}

		/**
		 * Whether to use Nimbus's typ header verification. This is {@code true} by
		 * default, however it may change to {@code false} in a future major release.
		 *
		 * <p>
		 * By turning off this feature, {@link NimbusReactiveJwtDecoder} expects
		 * applications to check the {@code typ} header themselves in order to determine
		 * what kind of validation is needed
		 * </p>
		 *
		 * <p>
		 * This is done for you when you use {@link JwtValidators} to construct a
		 * validator.
		 *
		 * <p>
		 * That means that this: <code>
		 *     NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder.withIssuerLocation(issuer).build();
		 *     jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer);
		 * </code>
		 *
		 * <p>
		 * Is equivalent to this: <code>
		 *     NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder.withIssuerLocation(issuer)
		 *         .validateType(false)
		 *         .build();
		 *     jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithValidators(
		 *     		new JwtIssuerValidator(issuer), JwtTypeValidator.jwt());
		 * </code>
		 *
		 * <p>
		 * The difference is that by setting this to {@code false}, it allows you to
		 * provide validation by type, like for {@code at+jwt}:
		 *
		 * <code>
		 *     NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder.withIssuerLocation(issuer)
		 *         .validateType(false)
		 *         .build();
		 *     jwtDecoder.setJwtValidator(new MyAtJwtValidator());
		 * </code>
		 * @param shouldValidateTypHeader whether Nimbus should validate the typ header or
		 * not
		 * @return a {@link JwkSetUriReactiveJwtDecoderBuilder} for further configurations
		 * @since 6.5
		 */
		public JwkSetUriReactiveJwtDecoderBuilder validateType(boolean shouldValidateTypHeader) {
			this.typeVerifier = shouldValidateTypHeader ? JWT_TYPE_VERIFIER : NO_TYPE_VERIFIER;
			return this;
		}

		/**
		 * Configure the list of
		 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target=
		 * "_blank">algorithms</a> to use with the given {@link Consumer}.
		 * @param signatureAlgorithmsConsumer a {@link Consumer} for further configuring
		 * the algorithm list
		 * @return a {@link JwkSetUriReactiveJwtDecoderBuilder} for further configurations
		 */
		public JwkSetUriReactiveJwtDecoderBuilder jwsAlgorithms(
				Consumer<Set<SignatureAlgorithm>> signatureAlgorithmsConsumer) {
			Assert.notNull(signatureAlgorithmsConsumer, "signatureAlgorithmsConsumer cannot be null");
			signatureAlgorithmsConsumer.accept(this.signatureAlgorithms);
			return this;
		}

		/**
		 * Use the given {@link WebClient} to coordinate with the authorization servers
		 * indicated in the <a href="https://tools.ietf.org/html/rfc7517#section-5">JWK
		 * Set</a> uri as well as the <a href=
		 * "https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a>.
		 * @param webClient
		 * @return a {@link JwkSetUriReactiveJwtDecoderBuilder} for further configurations
		 */
		public JwkSetUriReactiveJwtDecoderBuilder webClient(WebClient webClient) {
			Assert.notNull(webClient, "webClient cannot be null");
			this.webClient = webClient;
			return this;
		}

		/**
		 * Use the given {@link Consumer} to customize the {@link JWTProcessor
		 * ConfigurableJWTProcessor} before passing it to the build
		 * {@link NimbusReactiveJwtDecoder}.
		 * @param jwtProcessorCustomizer the callback used to alter the processor
		 * @return a {@link JwkSetUriReactiveJwtDecoderBuilder} for further configurations
		 * @since 5.4
		 */
		public JwkSetUriReactiveJwtDecoderBuilder jwtProcessorCustomizer(
				Consumer<ConfigurableJWTProcessor<JWKSecurityContext>> jwtProcessorCustomizer) {
			Assert.notNull(jwtProcessorCustomizer, "jwtProcessorCustomizer cannot be null");
			this.jwtProcessorCustomizer = (source, processor) -> {
				jwtProcessorCustomizer.accept(processor);
				return Mono.just(processor);
			};
			return this;
		}

		JwkSetUriReactiveJwtDecoderBuilder jwtProcessorCustomizer(
				BiFunction<ReactiveRemoteJWKSource, ConfigurableJWTProcessor<JWKSecurityContext>, Mono<ConfigurableJWTProcessor<JWKSecurityContext>>> jwtProcessorCustomizer) {
			Assert.notNull(jwtProcessorCustomizer, "jwtProcessorCustomizer cannot be null");
			this.jwtProcessorCustomizer = jwtProcessorCustomizer;
			return this;
		}

		/**
		 * Build the configured {@link NimbusReactiveJwtDecoder}.
		 * @return the configured {@link NimbusReactiveJwtDecoder}
		 */
		public NimbusReactiveJwtDecoder build() {
			return new NimbusReactiveJwtDecoder(processor());
		}

		Mono<JWSKeySelector<JWKSecurityContext>> jwsKeySelector(ReactiveRemoteJWKSource source) {
			JWKSecurityContextJWKSet jwkSource = new JWKSecurityContextJWKSet();
			if (this.signatureAlgorithms.isEmpty()) {
				return this.defaultAlgorithms.apply(source)
					.map((algorithms) -> new JWSVerificationKeySelector<>(algorithms, jwkSource));
			}
			Set<JWSAlgorithm> jwsAlgorithms = new HashSet<>();
			for (SignatureAlgorithm signatureAlgorithm : this.signatureAlgorithms) {
				JWSAlgorithm jwsAlgorithm = JWSAlgorithm.parse(signatureAlgorithm.getName());
				jwsAlgorithms.add(jwsAlgorithm);
			}
			return Mono.just(new JWSVerificationKeySelector<>(jwsAlgorithms, jwkSource));
		}

		Converter<JWT, Mono<JWTClaimsSet>> processor() {
			DefaultJWTProcessor<JWKSecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
			jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
			});
			ReactiveRemoteJWKSource source = new ReactiveRemoteJWKSource(this.jwkSetUri.apply(this.webClient));
			source.setWebClient(this.webClient);
			Mono<JWSKeySelector<JWKSecurityContext>> jwsKeySelector = jwsKeySelector(source);
			Mono<Tuple2<ConfigurableJWTProcessor<JWKSecurityContext>, Function<JWSAlgorithm, Boolean>>> jwtProcessorMono = jwsKeySelector
				.flatMap((selector) -> {
					jwtProcessor.setJWSKeySelector(selector);
					jwtProcessor.setJWSTypeVerifier(this.typeVerifier);
					return this.jwtProcessorCustomizer.apply(source, jwtProcessor);
				})
				.map((processor) -> Tuples.of(processor, getExpectedJwsAlgorithms(processor.getJWSKeySelector())))
				.cache((processor) -> FOREVER, (ex) -> Duration.ZERO, () -> Duration.ZERO);
			return (jwt) -> {
				return jwtProcessorMono.flatMap((tuple) -> {
					ConfigurableJWTProcessor<JWKSecurityContext> processor = tuple.getT1();
					Function<JWSAlgorithm, Boolean> expectedJwsAlgorithms = tuple.getT2();
					JWKSelector selector = createSelector(expectedJwsAlgorithms, jwt.getHeader());
					return source.get(selector)
						.onErrorMap((ex) -> new IllegalStateException("Could not obtain the keys", ex))
						.map((jwkList) -> createClaimsSet(processor, jwt, new JWKSecurityContext(jwkList)));
				});
			};
		}

		private Function<JWSAlgorithm, Boolean> getExpectedJwsAlgorithms(JWSKeySelector<?> jwsKeySelector) {
			if (jwsKeySelector instanceof JWSVerificationKeySelector) {
				return ((JWSVerificationKeySelector<?>) jwsKeySelector)::isAllowed;
			}
			throw new IllegalArgumentException("Unsupported key selector type " + jwsKeySelector.getClass());
		}

		private JWKSelector createSelector(Function<JWSAlgorithm, Boolean> expectedJwsAlgorithms, Header header) {
			JWSHeader jwsHeader = (JWSHeader) header;
			if (!expectedJwsAlgorithms.apply(jwsHeader.getAlgorithm())) {
				throw new BadJwtException("Unsupported algorithm of " + header.getAlgorithm());
			}
			return new JWKSelector(JWKMatcher.forJWSHeader(jwsHeader));
		}

	}

	/**
	 * A builder for creating {@link NimbusReactiveJwtDecoder} instances based on a public
	 * key.
	 *
	 * @since 5.2
	 */
	public static final class PublicKeyReactiveJwtDecoderBuilder {

		private static final JOSEObjectTypeVerifier<SecurityContext> JWT_TYPE_VERIFIER = new DefaultJOSEObjectTypeVerifier<>(
				JOSEObjectType.JWT, null);

		private static final JOSEObjectTypeVerifier<SecurityContext> NO_TYPE_VERIFIER = (header, context) -> {
		};

		private final RSAPublicKey key;

		private JWSAlgorithm jwsAlgorithm;

		private JOSEObjectTypeVerifier<SecurityContext> typeVerifier = JWT_TYPE_VERIFIER;

		private Consumer<ConfigurableJWTProcessor<SecurityContext>> jwtProcessorCustomizer;

		private PublicKeyReactiveJwtDecoderBuilder(RSAPublicKey key) {
			Assert.notNull(key, "key cannot be null");
			this.key = key;
			this.jwsAlgorithm = JWSAlgorithm.RS256;
			this.jwtProcessorCustomizer = (processor) -> {
			};
		}

		/**
		 * Use the given signing
		 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target=
		 * "_blank">algorithm</a>. The value should be one of
		 * <a href="https://tools.ietf.org/html/rfc7518#section-3.3" target=
		 * "_blank">RS256, RS384, or RS512</a>.
		 * @param signatureAlgorithm the algorithm to use
		 * @return a {@link PublicKeyReactiveJwtDecoderBuilder} for further configurations
		 */
		public PublicKeyReactiveJwtDecoderBuilder signatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
			Assert.notNull(signatureAlgorithm, "signatureAlgorithm cannot be null");
			this.jwsAlgorithm = JWSAlgorithm.parse(signatureAlgorithm.getName());
			return this;
		}

		/**
		 * Whether to use Nimbus's typ header verification. This is {@code true} by
		 * default, however it may change to {@code false} in a future major release.
		 *
		 * <p>
		 * By turning off this feature, {@link NimbusReactiveJwtDecoder} expects
		 * applications to check the {@code typ} header themselves in order to determine
		 * what kind of validation is needed
		 * </p>
		 *
		 * <p>
		 * This is done for you when you use {@link JwtValidators} to construct a
		 * validator.
		 *
		 * <p>
		 * That means that this: <code>
		 *     NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder.withIssuerLocation(issuer).build();
		 *     jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer);
		 * </code>
		 *
		 * <p>
		 * Is equivalent to this: <code>
		 *     NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder.withPublicKey(key)
		 *         .validateType(false)
		 *         .build();
		 *     jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithValidators(
		 *     		new JwtIssuerValidator(issuer), JwtTypeValidator.jwt());
		 *     		new JwtIssuerValidator(issuer), JwtTypeValidator.jwt());
		 * </code>
		 *
		 * <p>
		 * The difference is that by setting this to {@code false}, it allows you to
		 * provide validation by type, like for {@code at+jwt}:
		 *
		 * <code>
		 *     NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder.withPublicKey(key)
		 *         .validateType(false)
		 *         .build();
		 *     jwtDecoder.setJwtValidator(new MyAtJwtValidator());
		 * </code>
		 * @param shouldValidateTypHeader whether Nimbus should validate the typ header or
		 * not
		 * @return a {@link PublicKeyReactiveJwtDecoderBuilder} for further configurations
		 * @since 6.5
		 */
		public PublicKeyReactiveJwtDecoderBuilder validateType(boolean shouldValidateTypHeader) {
			this.typeVerifier = shouldValidateTypHeader ? JWT_TYPE_VERIFIER : NO_TYPE_VERIFIER;
			return this;
		}

		/**
		 * Use the given {@link Consumer} to customize the {@link JWTProcessor
		 * ConfigurableJWTProcessor} before passing it to the build
		 * {@link NimbusReactiveJwtDecoder}.
		 * @param jwtProcessorCustomizer the callback used to alter the processor
		 * @return a {@link PublicKeyReactiveJwtDecoderBuilder} for further configurations
		 * @since 5.4
		 */
		public PublicKeyReactiveJwtDecoderBuilder jwtProcessorCustomizer(
				Consumer<ConfigurableJWTProcessor<SecurityContext>> jwtProcessorCustomizer) {
			Assert.notNull(jwtProcessorCustomizer, "jwtProcessorCustomizer cannot be null");
			this.jwtProcessorCustomizer = jwtProcessorCustomizer;
			return this;
		}

		/**
		 * Build the configured {@link NimbusReactiveJwtDecoder}.
		 * @return the configured {@link NimbusReactiveJwtDecoder}
		 */
		public NimbusReactiveJwtDecoder build() {
			return new NimbusReactiveJwtDecoder(processor());
		}

		Converter<JWT, Mono<JWTClaimsSet>> processor() {
			Assert.state(JWSAlgorithm.Family.RSA.contains(this.jwsAlgorithm),
					() -> "The provided key is of type RSA; however the signature algorithm is of some other type: "
							+ this.jwsAlgorithm + ". Please indicate one of RS256, RS384, or RS512.");
			JWSKeySelector<SecurityContext> jwsKeySelector = new SingleKeyJWSKeySelector<>(this.jwsAlgorithm, this.key);
			DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
			jwtProcessor.setJWSKeySelector(jwsKeySelector);
			jwtProcessor.setJWSTypeVerifier(this.typeVerifier);
			// Spring Security validates the claim set independent from Nimbus
			jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
			});
			this.jwtProcessorCustomizer.accept(jwtProcessor);
			return (jwt) -> Mono.fromCallable(() -> createClaimsSet(jwtProcessor, jwt, null));
		}

	}

	/**
	 * A builder for creating {@link NimbusReactiveJwtDecoder} instances based on a
	 * {@code SecretKey}.
	 *
	 * @since 5.2
	 */
	public static final class SecretKeyReactiveJwtDecoderBuilder {

		private static final JOSEObjectTypeVerifier<SecurityContext> JWT_TYPE_VERIFIER = new DefaultJOSEObjectTypeVerifier<>(
				JOSEObjectType.JWT, null);

		private static final JOSEObjectTypeVerifier<SecurityContext> NO_TYPE_VERIFIER = (header, context) -> {
		};

		private final SecretKey secretKey;

		private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS256;

		private JOSEObjectTypeVerifier<SecurityContext> typeVerifier = JWT_TYPE_VERIFIER;

		private Consumer<ConfigurableJWTProcessor<SecurityContext>> jwtProcessorCustomizer;

		private SecretKeyReactiveJwtDecoderBuilder(SecretKey secretKey) {
			Assert.notNull(secretKey, "secretKey cannot be null");
			this.secretKey = secretKey;
			this.jwtProcessorCustomizer = (processor) -> {
			};
		}

		/**
		 * Use the given
		 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target=
		 * "_blank">algorithm</a> when generating the MAC.
		 *
		 * The value should be one of
		 * <a href="https://tools.ietf.org/html/rfc7518#section-3.2" target=
		 * "_blank">HS256, HS384 or HS512</a>.
		 * @param macAlgorithm the MAC algorithm to use
		 * @return a {@link SecretKeyReactiveJwtDecoderBuilder} for further configurations
		 */
		public SecretKeyReactiveJwtDecoderBuilder macAlgorithm(MacAlgorithm macAlgorithm) {
			Assert.notNull(macAlgorithm, "macAlgorithm cannot be null");
			this.jwsAlgorithm = JWSAlgorithm.parse(macAlgorithm.getName());
			return this;
		}

		/**
		 * Whether to use Nimbus's typ header verification. This is {@code true} by
		 * default, however it may change to {@code false} in a future major release.
		 *
		 * <p>
		 * By turning off this feature, {@link NimbusReactiveJwtDecoder} expects
		 * applications to check the {@code typ} header themselves in order to determine
		 * what kind of validation is needed
		 * </p>
		 *
		 * <p>
		 * This is done for you when you use {@link JwtValidators} to construct a
		 * validator.
		 *
		 * <p>
		 * That means that this: <code>
		 *     NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder.withIssuerLocation(issuer).build();
		 *     jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer);
		 * </code>
		 *
		 * <p>
		 * Is equivalent to this: <code>
		 *     NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder.withSecretKey(key)
		 *         .validateType(false)
		 *         .build();
		 *     jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithValidators(
		 *     		new JwtIssuerValidator(issuer), JwtTypeValidator.jwt());
		 * </code>
		 *
		 * <p>
		 * The difference is that by setting this to {@code false}, it allows you to
		 * provide validation by type, like for {@code at+jwt}:
		 *
		 * <code>
		 *     NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder.withSecretKey(key)
		 *         .validateType(false)
		 *         .build();
		 *     jwtDecoder.setJwtValidator(new MyAtJwtValidator());
		 * </code>
		 * @param shouldValidateTypHeader whether Nimbus should validate the typ header or
		 * not
		 * @return a {@link PublicKeyReactiveJwtDecoderBuilder} for further configurations
		 * @since 6.5
		 */
		public SecretKeyReactiveJwtDecoderBuilder validateType(boolean shouldValidateTypHeader) {
			this.typeVerifier = shouldValidateTypHeader ? JWT_TYPE_VERIFIER : NO_TYPE_VERIFIER;
			return this;
		}

		/**
		 * Use the given {@link Consumer} to customize the {@link JWTProcessor
		 * ConfigurableJWTProcessor} before passing it to the build
		 * {@link NimbusReactiveJwtDecoder}.
		 * @param jwtProcessorCustomizer the callback used to alter the processor
		 * @return a {@link SecretKeyReactiveJwtDecoderBuilder} for further configurations
		 * @since 5.4
		 */
		public SecretKeyReactiveJwtDecoderBuilder jwtProcessorCustomizer(
				Consumer<ConfigurableJWTProcessor<SecurityContext>> jwtProcessorCustomizer) {
			Assert.notNull(jwtProcessorCustomizer, "jwtProcessorCustomizer cannot be null");
			this.jwtProcessorCustomizer = jwtProcessorCustomizer;
			return this;
		}

		/**
		 * Build the configured {@link NimbusReactiveJwtDecoder}.
		 * @return the configured {@link NimbusReactiveJwtDecoder}
		 */
		public NimbusReactiveJwtDecoder build() {
			return new NimbusReactiveJwtDecoder(processor());
		}

		Converter<JWT, Mono<JWTClaimsSet>> processor() {
			JWSKeySelector<SecurityContext> jwsKeySelector = new SingleKeyJWSKeySelector<>(this.jwsAlgorithm,
					this.secretKey);
			DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
			jwtProcessor.setJWSKeySelector(jwsKeySelector);
			jwtProcessor.setJWSTypeVerifier(this.typeVerifier);
			// Spring Security validates the claim set independent from Nimbus
			jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
			});
			this.jwtProcessorCustomizer.accept(jwtProcessor);
			return (jwt) -> Mono.fromCallable(() -> createClaimsSet(jwtProcessor, jwt, null));
		}

	}

	/**
	 * A builder for creating {@link NimbusReactiveJwtDecoder} instances.
	 *
	 * @since 5.2
	 */
	public static final class JwkSourceReactiveJwtDecoderBuilder {

		private static final JOSEObjectTypeVerifier<JWKSecurityContext> JWT_TYPE_VERIFIER = new DefaultJOSEObjectTypeVerifier<>(
				JOSEObjectType.JWT, null);

		private static final JOSEObjectTypeVerifier<JWKSecurityContext> NO_TYPE_VERIFIER = (header, context) -> {
		};

		private final Function<SignedJWT, Flux<JWK>> jwkSource;

		private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.RS256;

		private JOSEObjectTypeVerifier<JWKSecurityContext> typeVerifier = JWT_TYPE_VERIFIER;

		private Consumer<ConfigurableJWTProcessor<JWKSecurityContext>> jwtProcessorCustomizer;

		private JwkSourceReactiveJwtDecoderBuilder(Function<SignedJWT, Flux<JWK>> jwkSource) {
			Assert.notNull(jwkSource, "jwkSource cannot be null");
			this.jwkSource = jwkSource;
			this.jwtProcessorCustomizer = (processor) -> {
			};
		}

		/**
		 * Use the given signing
		 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target=
		 * "_blank">algorithm</a>.
		 * @param jwsAlgorithm the algorithm to use
		 * @return a {@link JwkSourceReactiveJwtDecoderBuilder} for further configurations
		 */
		public JwkSourceReactiveJwtDecoderBuilder jwsAlgorithm(JwsAlgorithm jwsAlgorithm) {
			Assert.notNull(jwsAlgorithm, "jwsAlgorithm cannot be null");
			this.jwsAlgorithm = JWSAlgorithm.parse(jwsAlgorithm.getName());
			return this;
		}

		/**
		 * Whether to use Nimbus's typ header verification. This is {@code true} by
		 * default, however it may change to {@code false} in a future major release.
		 *
		 * <p>
		 * By turning off this feature, {@link NimbusReactiveJwtDecoder} expects
		 * applications to check the {@code typ} header themselves in order to determine
		 * what kind of validation is needed
		 * </p>
		 *
		 * <p>
		 * This is done for you when you use {@link JwtValidators} to construct a
		 * validator.
		 *
		 * <p>
		 * That means that this: <code>
		 *     NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder.withJwkSource(issuer).build();
		 *     jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer);
		 * </code>
		 *
		 * <p>
		 * Is equivalent to this: <code>
		 *     NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder.withJwkSource(key)
		 *         .validateType(false)
		 *         .build();
		 *     jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithValidators(
		 *     		new JwtIssuerValidator(issuer), JwtTypeValidator.jwt());
		 * </code>
		 *
		 * <p>
		 * The difference is that by setting this to {@code false}, it allows you to
		 * provide validation by type, like for {@code at+jwt}:
		 *
		 * <code>
		 *     NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder.withJwkSource(key)
		 *         .validateType(false)
		 *         .build();
		 *     jwtDecoder.setJwtValidator(new MyAtJwtValidator());
		 * </code>
		 * @param shouldValidateTypHeader whether Nimbus should validate the typ header or
		 * not
		 * @return a {@link JwkSourceReactiveJwtDecoderBuilder} for further configurations
		 * @since 6.5
		 */
		public JwkSourceReactiveJwtDecoderBuilder validateType(boolean shouldValidateTypHeader) {
			this.typeVerifier = shouldValidateTypHeader ? JWT_TYPE_VERIFIER : NO_TYPE_VERIFIER;
			return this;
		}

		/**
		 * Use the given {@link Consumer} to customize the {@link JWTProcessor
		 * ConfigurableJWTProcessor} before passing it to the build
		 * {@link NimbusReactiveJwtDecoder}.
		 * @param jwtProcessorCustomizer the callback used to alter the processor
		 * @return a {@link JwkSourceReactiveJwtDecoderBuilder} for further configurations
		 * @since 5.4
		 */
		public JwkSourceReactiveJwtDecoderBuilder jwtProcessorCustomizer(
				Consumer<ConfigurableJWTProcessor<JWKSecurityContext>> jwtProcessorCustomizer) {
			Assert.notNull(jwtProcessorCustomizer, "jwtProcessorCustomizer cannot be null");
			this.jwtProcessorCustomizer = jwtProcessorCustomizer;
			return this;
		}

		/**
		 * Build the configured {@link NimbusReactiveJwtDecoder}.
		 * @return the configured {@link NimbusReactiveJwtDecoder}
		 */
		public NimbusReactiveJwtDecoder build() {
			return new NimbusReactiveJwtDecoder(processor());
		}

		Converter<JWT, Mono<JWTClaimsSet>> processor() {
			JWKSecurityContextJWKSet jwkSource = new JWKSecurityContextJWKSet();
			JWSKeySelector<JWKSecurityContext> jwsKeySelector = new JWSVerificationKeySelector<>(this.jwsAlgorithm,
					jwkSource);
			DefaultJWTProcessor<JWKSecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
			jwtProcessor.setJWSKeySelector(jwsKeySelector);
			jwtProcessor.setJWSTypeVerifier(this.typeVerifier);
			jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
			});
			this.jwtProcessorCustomizer.accept(jwtProcessor);
			return (jwt) -> {
				if (jwt instanceof SignedJWT) {
					return this.jwkSource.apply((SignedJWT) jwt)
						.onErrorMap((e) -> new IllegalStateException("Could not obtain the keys", e))
						.collectList()
						.map((jwks) -> createClaimsSet(jwtProcessor, jwt, new JWKSecurityContext(jwks)));
				}
				throw new BadJwtException("Unsupported algorithm of " + jwt.getHeader().getAlgorithm());
			};
		}

	}

}
