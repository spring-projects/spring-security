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

import java.net.URI;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;
import java.util.function.Function;

import javax.crypto.SecretKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSetCacheRefreshEvaluator;
import com.nimbusds.jose.jwk.source.JWKSetSource;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.proc.SingleKeyJWSKeySelector;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.cache.Cache;
import org.springframework.cache.support.NoOpCache;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * A low-level Nimbus implementation of {@link JwtDecoder} which takes a raw Nimbus
 * configuration.
 *
 * @author Josh Cummings
 * @author Joe Grandja
 * @author Mykyta Bezverkhyi
 * @author Daeho Kwon
 * @author Andrey Litvitski
 * @since 5.2
 */
public final class NimbusJwtDecoder implements JwtDecoder {

	private final Log logger = LogFactory.getLog(getClass());

	private static final String DECODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to decode the Jwt: %s";

	private final JWTProcessor<SecurityContext> jwtProcessor;

	private Converter<Map<String, Object>, Map<String, Object>> claimSetConverter = MappedJwtClaimSetConverter
		.withDefaults(Collections.emptyMap());

	private OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators.createDefault();

	/**
	 * Configures a {@link NimbusJwtDecoder} with the given parameters
	 * @param jwtProcessor - the {@link JWTProcessor} to use
	 */
	public NimbusJwtDecoder(JWTProcessor<SecurityContext> jwtProcessor) {
		Assert.notNull(jwtProcessor, "jwtProcessor cannot be null");
		this.jwtProcessor = jwtProcessor;
	}

	/**
	 * Use this {@link Jwt} Validator
	 * @param jwtValidator - the Jwt Validator to use
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

	/**
	 * Decode and validate the JWT from its compact claims representation format
	 * @param token the JWT value
	 * @return a validated {@link Jwt}
	 * @throws JwtException when the token is malformed or otherwise invalid
	 */
	@Override
	public Jwt decode(String token) throws JwtException {
		JWT jwt = parse(token);
		if (jwt instanceof PlainJWT) {
			this.logger.trace("Failed to decode unsigned token");
			throw new BadJwtException("Unsupported algorithm of " + jwt.getHeader().getAlgorithm());
		}
		Jwt createdJwt = createJwt(token, jwt);
		return validateJwt(createdJwt);
	}

	private JWT parse(String token) {
		try {
			return JWTParser.parse(token);
		}
		catch (Exception ex) {
			this.logger.trace("Failed to parse token", ex);
			if (ex instanceof ParseException) {
				throw new BadJwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, "Malformed token"), ex);
			}
			throw new BadJwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
		}
	}

	private Jwt createJwt(String token, JWT parsedJwt) {
		try {
			// Verify the signature
			JWTClaimsSet jwtClaimsSet = this.jwtProcessor.process(parsedJwt, null);
			Map<String, Object> headers = new LinkedHashMap<>(parsedJwt.getHeader().toJSONObject());
			Map<String, Object> claims = this.claimSetConverter.convert(jwtClaimsSet.getClaims());
			// @formatter:off
			return Jwt.withTokenValue(token)
					.headers((h) -> h.putAll(headers))
					.claims((c) -> c.putAll(claims))
					.build();
			// @formatter:on
		}
		catch (RemoteKeySourceException ex) {
			this.logger.trace("Failed to retrieve JWK set", ex);
			if (ex.getCause() instanceof ParseException) {
				throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, "Malformed Jwk set"), ex);
			}
			throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
		}
		catch (JOSEException ex) {
			this.logger.trace("Failed to process JWT", ex);
			throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
		}
		catch (Exception ex) {
			this.logger.trace("Failed to process JWT", ex);
			if (ex.getCause() instanceof ParseException) {
				throw new BadJwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, "Malformed payload"), ex);
			}
			throw new BadJwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
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
				return String.format(DECODING_ERROR_MESSAGE_TEMPLATE, oAuth2Error.getDescription());
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
	 * @return a {@link JwkSetUriJwtDecoderBuilder} that will derive the JWK Set uri when
	 * {@link JwkSetUriJwtDecoderBuilder#build} is called
	 * @since 6.1
	 * @see JwtDecoders
	 */
	public static JwkSetUriJwtDecoderBuilder withIssuerLocation(String issuer) {
		return new JwkSetUriJwtDecoderBuilder((rest) -> {
			Map<String, Object> configuration = JwtDecoderProviderConfigurationUtils
				.getConfigurationForIssuerLocation(issuer, rest);
			JwtDecoderProviderConfigurationUtils.validateIssuer(configuration, issuer);
			return configuration.get("jwks_uri").toString();
		}, JwtDecoderProviderConfigurationUtils::getJWSAlgorithms);
	}

	/**
	 * Use the given <a href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</a>
	 * uri.
	 * @param jwkSetUri the JWK Set uri to use
	 * @return a {@link JwkSetUriJwtDecoderBuilder} for further configurations
	 */
	public static JwkSetUriJwtDecoderBuilder withJwkSetUri(String jwkSetUri) {
		return new JwkSetUriJwtDecoderBuilder(jwkSetUri);
	}

	/**
	 * Use the given public key to validate JWTs
	 * @param key the public key to use
	 * @return a {@link PublicKeyJwtDecoderBuilder} for further configurations
	 */
	public static PublicKeyJwtDecoderBuilder withPublicKey(RSAPublicKey key) {
		return new PublicKeyJwtDecoderBuilder(key);
	}

	/**
	 * Use the given {@code SecretKey} to validate the MAC on a JSON Web Signature (JWS).
	 * @param secretKey the {@code SecretKey} used to validate the MAC
	 * @return a {@link SecretKeyJwtDecoderBuilder} for further configurations
	 */
	public static SecretKeyJwtDecoderBuilder withSecretKey(SecretKey secretKey) {
		return new SecretKeyJwtDecoderBuilder(secretKey);
	}

	/**
	 * Use the given {@code JWKSource} to create a JwkSourceJwtDecoderBuilder.
	 * @param jwkSource the JWK Source to use
	 * @return a {@link JwkSetUriJwtDecoderBuilder} for further configurations
	 * @since 7.0
	 */
	public static JwkSourceJwtDecoderBuilder withJwkSource(JWKSource<SecurityContext> jwkSource) {
		return new JwkSourceJwtDecoderBuilder(jwkSource);
	}

	/**
	 * A builder for creating {@link NimbusJwtDecoder} instances based on a
	 * <a target="_blank" href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</a>
	 * uri.
	 */
	public static final class JwkSetUriJwtDecoderBuilder {

		private static final JOSEObjectTypeVerifier<SecurityContext> JWT_TYPE_VERIFIER = new DefaultJOSEObjectTypeVerifier<>(
				JOSEObjectType.JWT, null);

		private static final JOSEObjectTypeVerifier<SecurityContext> NO_TYPE_VERIFIER = (header, context) -> {
		};

		private final Function<RestOperations, String> jwkSetUri;

		private Function<JWKSource<SecurityContext>, Set<JWSAlgorithm>> defaultAlgorithms = (source) -> Set
			.of(JWSAlgorithm.RS256);

		private JOSEObjectTypeVerifier<SecurityContext> typeVerifier = NO_TYPE_VERIFIER;

		private final Set<SignatureAlgorithm> signatureAlgorithms = new HashSet<>();

		private RestOperations restOperations = new RestTemplateWithNimbusDefaultTimeouts();

		private Cache cache = new NoOpCache("default");

		private Consumer<ConfigurableJWTProcessor<SecurityContext>> jwtProcessorCustomizer;

		private JwkSetUriJwtDecoderBuilder(String jwkSetUri) {
			Assert.hasText(jwkSetUri, "jwkSetUri cannot be empty");
			this.jwkSetUri = (rest) -> jwkSetUri;
			this.jwtProcessorCustomizer = (processor) -> {
			};
		}

		private JwkSetUriJwtDecoderBuilder(Function<RestOperations, String> jwkSetUri,
				Function<JWKSource<SecurityContext>, Set<JWSAlgorithm>> defaultAlgorithms) {
			Assert.notNull(jwkSetUri, "jwkSetUri function cannot be null");
			Assert.notNull(defaultAlgorithms, "defaultAlgorithms function cannot be null");
			this.jwkSetUri = jwkSetUri;
			this.defaultAlgorithms = defaultAlgorithms;
			this.jwtProcessorCustomizer = (processor) -> {
			};
		}

		/**
		 * Whether to use Nimbus's {@code typ} header verification. This is {@code false}
		 * by default.
		 *
		 * <p>
		 * By turning on this feature, {@link NimbusJwtDecoder} will delegate checking the
		 * {@code typ} header to Nimbus by using Nimbus's default
		 * {@link JOSEObjectTypeVerifier}.
		 * </p>
		 *
		 * <p>
		 * When this is set to {@code false}, this: <code>
		 *     NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withIssuerLocation(issuer).build();
		 *     jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer);
		 * </code>
		 *
		 * <p>
		 * Is equivalent to this: <code>
		 *     NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withIssuerLocation(issuer)
		 *         .validateType(false)
		 *         .build();
		 *     jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithValidators(
		 *     		new JwtIssuerValidator(issuer), JwtTypeValidator.jwt());
		 * </code>
		 *
		 * <p>
		 * The difference is that by setting this to {@code false}, it allows you to
		 * provide validation by type, like for {@code at+jwt}: <code>
		 *     NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withIssuerLocation(issuer)
		 *         .validateType(false)
		 *         .build();
		 *     jwtDecoder.setJwtValidator(new MyAtJwtValidator());
		 * </code>
		 * @param shouldValidateTypHeader whether Nimbus should validate the typ header or
		 * not
		 * @return a {@link JwkSetUriJwtDecoderBuilder} for further configurations
		 * @since 6.5
		 */
		public JwkSetUriJwtDecoderBuilder validateType(boolean shouldValidateTypHeader) {
			this.typeVerifier = shouldValidateTypHeader ? JWT_TYPE_VERIFIER : NO_TYPE_VERIFIER;
			return this;
		}

		/**
		 * Append the given signing
		 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target=
		 * "_blank">algorithm</a> to the set of algorithms to use.
		 * @param signatureAlgorithm the algorithm to use
		 * @return a {@link JwkSetUriJwtDecoderBuilder} for further configurations
		 */
		public JwkSetUriJwtDecoderBuilder jwsAlgorithm(SignatureAlgorithm signatureAlgorithm) {
			Assert.notNull(signatureAlgorithm, "signatureAlgorithm cannot be null");
			this.signatureAlgorithms.add(signatureAlgorithm);
			return this;
		}

		/**
		 * Configure the list of
		 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target=
		 * "_blank">algorithms</a> to use with the given {@link Consumer}.
		 * @param signatureAlgorithmsConsumer a {@link Consumer} for further configuring
		 * the algorithm list
		 * @return a {@link JwkSetUriJwtDecoderBuilder} for further configurations
		 */
		public JwkSetUriJwtDecoderBuilder jwsAlgorithms(Consumer<Set<SignatureAlgorithm>> signatureAlgorithmsConsumer) {
			Assert.notNull(signatureAlgorithmsConsumer, "signatureAlgorithmsConsumer cannot be null");
			signatureAlgorithmsConsumer.accept(this.signatureAlgorithms);
			return this;
		}

		/**
		 * Use the given {@link RestOperations} to coordinate with the authorization
		 * servers indicated in the
		 * <a href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</a> uri as well
		 * as the <a href=
		 * "https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a>.
		 * @param restOperations the {@link RestOperations} instance to use
		 * @return a {@link JwkSetUriJwtDecoderBuilder} for further configurations
		 */
		public JwkSetUriJwtDecoderBuilder restOperations(RestOperations restOperations) {
			Assert.notNull(restOperations, "restOperations cannot be null");
			this.restOperations = restOperations;
			return this;
		}

		/**
		 * Use the given {@link Cache} to store
		 * <a href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</a>.
		 * @param cache the {@link Cache} to be used to store JWK Set
		 * @return a {@link JwkSetUriJwtDecoderBuilder} for further configurations
		 * @since 5.4
		 */
		public JwkSetUriJwtDecoderBuilder cache(Cache cache) {
			Assert.notNull(cache, "cache cannot be null");
			this.cache = cache;
			return this;
		}

		/**
		 * Enables discovery of supported JWS algorithms from the remote JWK Set.
		 * @return a {@link JwkSetUriJwtDecoderBuilder} for further configuration
		 * @since 7.0.0
		 */
		public JwkSetUriJwtDecoderBuilder discoverJwsAlgorithms() {
			this.defaultAlgorithms = JwtDecoderProviderConfigurationUtils::getJWSAlgorithms;
			return this;
		}

		/**
		 * Use the given {@link Consumer} to customize the {@link JWTProcessor
		 * ConfigurableJWTProcessor} before passing it to the build
		 * {@link NimbusJwtDecoder}.
		 * @param jwtProcessorCustomizer the callback used to alter the processor
		 * @return a {@link JwkSetUriJwtDecoderBuilder} for further configurations
		 * @since 5.4
		 */
		public JwkSetUriJwtDecoderBuilder jwtProcessorCustomizer(
				Consumer<ConfigurableJWTProcessor<SecurityContext>> jwtProcessorCustomizer) {
			Assert.notNull(jwtProcessorCustomizer, "jwtProcessorCustomizer cannot be null");
			this.jwtProcessorCustomizer = jwtProcessorCustomizer;
			return this;
		}

		JWSKeySelector<SecurityContext> jwsKeySelector(JWKSource<SecurityContext> jwkSource) {
			if (this.signatureAlgorithms.isEmpty()) {
				return new JWSVerificationKeySelector<>(this.defaultAlgorithms.apply(jwkSource), jwkSource);
			}
			Set<JWSAlgorithm> jwsAlgorithms = new HashSet<>();
			for (SignatureAlgorithm signatureAlgorithm : this.signatureAlgorithms) {
				JWSAlgorithm jwsAlgorithm = JWSAlgorithm.parse(signatureAlgorithm.getName());
				jwsAlgorithms.add(jwsAlgorithm);
			}
			return new JWSVerificationKeySelector<>(jwsAlgorithms, jwkSource);
		}

		JWKSource<SecurityContext> jwkSource() {
			String jwkSetUri = this.jwkSetUri.apply(this.restOperations);
			return JWKSourceBuilder.create(new SpringJWKSource<>(this.restOperations, this.cache, jwkSetUri))
				.refreshAheadCache(false)
				.rateLimited(false)
				.cache(this.cache instanceof NoOpCache)
				.build();
		}

		JWTProcessor<SecurityContext> processor() {
			JWKSource<SecurityContext> jwkSource = jwkSource();
			ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
			jwtProcessor.setJWSTypeVerifier(this.typeVerifier);
			jwtProcessor.setJWSKeySelector(jwsKeySelector(jwkSource));
			// Spring Security validates the claim set independent from Nimbus
			jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
			});
			this.jwtProcessorCustomizer.accept(jwtProcessor);
			return jwtProcessor;
		}

		/**
		 * Build the configured {@link NimbusJwtDecoder}.
		 * @return the configured {@link NimbusJwtDecoder}
		 */
		public NimbusJwtDecoder build() {
			return new NimbusJwtDecoder(processor());
		}

		private static final class SpringJWKSource<C extends SecurityContext> implements JWKSetSource<C> {

			private static final MediaType APPLICATION_JWK_SET_JSON = new MediaType("application", "jwk-set+json");

			private final ReentrantLock reentrantLock = new ReentrantLock();

			private final RestOperations restOperations;

			private final Cache cache;

			private final String jwkSetUri;

			private JWKSet jwkSet;

			private SpringJWKSource(RestOperations restOperations, Cache cache, String jwkSetUri) {
				Assert.notNull(restOperations, "restOperations cannot be null");
				this.restOperations = restOperations;
				this.cache = cache;
				this.jwkSetUri = jwkSetUri;
				String jwks = this.cache.get(this.jwkSetUri, String.class);
				if (jwks != null) {
					try {
						this.jwkSet = JWKSet.parse(jwks);
					}
					catch (ParseException ignored) {
						// Ignore invalid cache value
					}
				}
			}

			private String fetchJwks() throws Exception {
				HttpHeaders headers = new HttpHeaders();
				headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON, APPLICATION_JWK_SET_JSON));
				RequestEntity<Void> request = new RequestEntity<>(headers, HttpMethod.GET, URI.create(this.jwkSetUri));
				ResponseEntity<String> response = this.restOperations.exchange(request, String.class);
				String jwks = response.getBody();
				this.jwkSet = JWKSet.parse(jwks);
				return jwks;
			}

			@Override
			public JWKSet getJWKSet(JWKSetCacheRefreshEvaluator refreshEvaluator, long currentTime, C context)
					throws KeySourceException {
				try {
					this.reentrantLock.lock();
					if (refreshEvaluator.requiresRefresh(this.jwkSet)) {
						this.cache.invalidate();
					}
					this.cache.get(this.jwkSetUri, this::fetchJwks);
					return this.jwkSet;
				}
				catch (Cache.ValueRetrievalException ex) {
					if (ex.getCause() instanceof RemoteKeySourceException keys) {
						throw keys;
					}
					throw new RemoteKeySourceException(ex.getCause().getMessage(), ex.getCause());
				}
				finally {
					this.reentrantLock.unlock();
				}
			}

			@Override
			public void close() {

			}

		}

	}

	/**
	 * A RestTemplate with timeouts configured to avoid blocking indefinitely when
	 * fetching JWK Sets while holding the reentrantLock.
	 */
	private static final class RestTemplateWithNimbusDefaultTimeouts extends RestTemplate {

		private RestTemplateWithNimbusDefaultTimeouts() {
			SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
			requestFactory.setConnectTimeout(RemoteJWKSet.resolveDefaultHTTPConnectTimeout());
			requestFactory.setReadTimeout(RemoteJWKSet.resolveDefaultHTTPReadTimeout());
			setRequestFactory(requestFactory);
		}

	}

	/**
	 * A builder for creating {@link NimbusJwtDecoder} instances based on a public key.
	 */
	public static final class PublicKeyJwtDecoderBuilder {

		private static final JOSEObjectTypeVerifier<SecurityContext> JWT_TYPE_VERIFIER = new DefaultJOSEObjectTypeVerifier<>(
				JOSEObjectType.JWT, null);

		private static final JOSEObjectTypeVerifier<SecurityContext> NO_TYPE_VERIFIER = (header, context) -> {
		};

		private JWSAlgorithm jwsAlgorithm;

		private JOSEObjectTypeVerifier<SecurityContext> typeVerifier = NO_TYPE_VERIFIER;

		private final RSAPublicKey key;

		private Consumer<ConfigurableJWTProcessor<SecurityContext>> jwtProcessorCustomizer;

		private PublicKeyJwtDecoderBuilder(RSAPublicKey key) {
			Assert.notNull(key, "key cannot be null");
			this.jwsAlgorithm = JWSAlgorithm.RS256;
			this.key = key;
			this.jwtProcessorCustomizer = (processor) -> {
			};
		}

		/**
		 * Whether to use Nimbus's {@code typ} header verification. This is {@code false}
		 * by default.
		 *
		 * <p>
		 * By turning on this feature, {@link NimbusJwtDecoder} will delegate checking the
		 * {@code typ} header to Nimbus by using Nimbus's default
		 * {@link JOSEObjectTypeVerifier}.
		 * </p>
		 *
		 * <p>
		 * When this is set to {@code false}, this: <code>
		 *     NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withIssuerLocation(issuer).build();
		 *     jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer);
		 * </code>
		 *
		 * <p>
		 * Is equivalent to this: <code>
		 *     NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withIssuerLocation(issuer)
		 *         .validateType(false)
		 *         .build();
		 *     jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithValidators(
		 *     		new JwtIssuerValidator(issuer), JwtTypeValidator.jwt());
		 * </code>
		 *
		 * <p>
		 * The difference is that by setting this to {@code false}, it allows you to
		 * provide validation by type, like for {@code at+jwt}: <code>
		 *     NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withIssuerLocation(issuer)
		 *         .validateType(false)
		 *         .build();
		 *     jwtDecoder.setJwtValidator(new MyAtJwtValidator());
		 * </code>
		 * @param shouldValidateTypHeader whether Nimbus should validate the typ header or
		 * not
		 * @return a {@link JwkSetUriJwtDecoderBuilder} for further configurations
		 * @since 6.5
		 */
		public PublicKeyJwtDecoderBuilder validateType(boolean shouldValidateTypHeader) {
			this.typeVerifier = shouldValidateTypHeader ? JWT_TYPE_VERIFIER : NO_TYPE_VERIFIER;
			return this;
		}

		/**
		 * Use the given signing
		 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target=
		 * "_blank">algorithm</a>. The value should be one of
		 * <a href="https://tools.ietf.org/html/rfc7518#section-3.3" target=
		 * "_blank">RS256, RS384, or RS512</a>.
		 * @param signatureAlgorithm the algorithm to use
		 * @return a {@link PublicKeyJwtDecoderBuilder} for further configurations
		 */
		public PublicKeyJwtDecoderBuilder signatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
			Assert.notNull(signatureAlgorithm, "signatureAlgorithm cannot be null");
			this.jwsAlgorithm = JWSAlgorithm.parse(signatureAlgorithm.getName());
			return this;
		}

		/**
		 * Use the given {@link Consumer} to customize the {@link JWTProcessor
		 * ConfigurableJWTProcessor} before passing it to the build
		 * {@link NimbusJwtDecoder}.
		 * @param jwtProcessorCustomizer the callback used to alter the processor
		 * @return a {@link PublicKeyJwtDecoderBuilder} for further configurations
		 * @since 5.4
		 */
		public PublicKeyJwtDecoderBuilder jwtProcessorCustomizer(
				Consumer<ConfigurableJWTProcessor<SecurityContext>> jwtProcessorCustomizer) {
			Assert.notNull(jwtProcessorCustomizer, "jwtProcessorCustomizer cannot be null");
			this.jwtProcessorCustomizer = jwtProcessorCustomizer;
			return this;
		}

		JWTProcessor<SecurityContext> processor() {
			Assert.state(JWSAlgorithm.Family.RSA.contains(this.jwsAlgorithm),
					() -> "The provided key is of type RSA; however the signature algorithm is of some other type: "
							+ this.jwsAlgorithm + ". Please indicate one of RS256, RS384, or RS512.");
			JWSKeySelector<SecurityContext> jwsKeySelector = new SingleKeyJWSKeySelector<>(this.jwsAlgorithm, this.key);
			DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
			jwtProcessor.setJWSTypeVerifier(this.typeVerifier);
			jwtProcessor.setJWSKeySelector(jwsKeySelector);
			// Spring Security validates the claim set independent from Nimbus
			jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
			});
			this.jwtProcessorCustomizer.accept(jwtProcessor);
			return jwtProcessor;
		}

		/**
		 * Build the configured {@link NimbusJwtDecoder}.
		 * @return the configured {@link NimbusJwtDecoder}
		 */
		public NimbusJwtDecoder build() {
			return new NimbusJwtDecoder(processor());
		}

	}

	/**
	 * A builder for creating {@link NimbusJwtDecoder} instances based on a
	 * {@code SecretKey}.
	 */
	public static final class SecretKeyJwtDecoderBuilder {

		private static final JOSEObjectTypeVerifier<SecurityContext> JWT_TYPE_VERIFIER = new DefaultJOSEObjectTypeVerifier<>(
				JOSEObjectType.JWT, null);

		private static final JOSEObjectTypeVerifier<SecurityContext> NO_TYPE_VERIFIER = (header, context) -> {
		};

		private final SecretKey secretKey;

		private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS256;

		private JOSEObjectTypeVerifier<SecurityContext> typeVerifier = NO_TYPE_VERIFIER;

		private Consumer<ConfigurableJWTProcessor<SecurityContext>> jwtProcessorCustomizer;

		private SecretKeyJwtDecoderBuilder(SecretKey secretKey) {
			Assert.notNull(secretKey, "secretKey cannot be null");
			this.secretKey = secretKey;
			this.jwtProcessorCustomizer = (processor) -> {
			};
		}

		/**
		 * Whether to use Nimbus's {@code typ} header verification. This is {@code false}
		 * by default.
		 *
		 * <p>
		 * By turning on this feature, {@link NimbusJwtDecoder} will delegate checking the
		 * {@code typ} header to Nimbus by using Nimbus's default
		 * {@link JOSEObjectTypeVerifier}.
		 * </p>
		 *
		 * <p>
		 * When this is set to {@code false}, this: <code>
		 *     NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withIssuerLocation(issuer).build();
		 *     jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer);
		 * </code>
		 *
		 * <p>
		 * Is equivalent to this: <code>
		 *     NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withIssuerLocation(issuer)
		 *         .validateType(false)
		 *         .build();
		 *     jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithValidators(
		 *     		new JwtIssuerValidator(issuer), JwtTypeValidator.jwt());
		 * </code>
		 *
		 * <p>
		 * The difference is that by setting this to {@code false}, it allows you to
		 * provide validation by type, like for {@code at+jwt}: <code>
		 *     NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withIssuerLocation(issuer)
		 *         .validateType(false)
		 *         .build();
		 *     jwtDecoder.setJwtValidator(new MyAtJwtValidator());
		 * </code>
		 * @param shouldValidateTypHeader whether Nimbus should validate the typ header or
		 * not
		 * @return a {@link JwkSetUriJwtDecoderBuilder} for further configurations
		 * @since 6.5
		 */
		public SecretKeyJwtDecoderBuilder validateType(boolean shouldValidateTypHeader) {
			this.typeVerifier = shouldValidateTypHeader ? JWT_TYPE_VERIFIER : NO_TYPE_VERIFIER;
			return this;
		}

		/**
		 * Use the given
		 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target=
		 * "_blank">algorithm</a> when generating the MAC. The value should be one of
		 * <a href="https://tools.ietf.org/html/rfc7518#section-3.2" target=
		 * "_blank">HS256, HS384 or HS512</a>.
		 * @param macAlgorithm the MAC algorithm to use
		 * @return a {@link SecretKeyJwtDecoderBuilder} for further configurations
		 */
		public SecretKeyJwtDecoderBuilder macAlgorithm(MacAlgorithm macAlgorithm) {
			Assert.notNull(macAlgorithm, "macAlgorithm cannot be null");
			this.jwsAlgorithm = JWSAlgorithm.parse(macAlgorithm.getName());
			return this;
		}

		/**
		 * Use the given {@link Consumer} to customize the {@link JWTProcessor
		 * ConfigurableJWTProcessor} before passing it to the build
		 * {@link NimbusJwtDecoder}.
		 * @param jwtProcessorCustomizer the callback used to alter the processor
		 * @return a {@link SecretKeyJwtDecoderBuilder} for further configurations
		 * @since 5.4
		 */
		public SecretKeyJwtDecoderBuilder jwtProcessorCustomizer(
				Consumer<ConfigurableJWTProcessor<SecurityContext>> jwtProcessorCustomizer) {
			Assert.notNull(jwtProcessorCustomizer, "jwtProcessorCustomizer cannot be null");
			this.jwtProcessorCustomizer = jwtProcessorCustomizer;
			return this;
		}

		/**
		 * Build the configured {@link NimbusJwtDecoder}.
		 * @return the configured {@link NimbusJwtDecoder}
		 */
		public NimbusJwtDecoder build() {
			return new NimbusJwtDecoder(processor());
		}

		JWTProcessor<SecurityContext> processor() {
			JWSKeySelector<SecurityContext> jwsKeySelector = new SingleKeyJWSKeySelector<>(this.jwsAlgorithm,
					this.secretKey);
			DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
			jwtProcessor.setJWSKeySelector(jwsKeySelector);
			jwtProcessor.setJWSTypeVerifier(this.typeVerifier);
			// Spring Security validates the claim set independent from Nimbus
			jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
			});
			this.jwtProcessorCustomizer.accept(jwtProcessor);
			return jwtProcessor;
		}

	}

	/**
	 * A builder for creating {@link NimbusJwtDecoder} instances based on a
	 * {@code JWKSource}.
	 *
	 * @since 7.0
	 */
	public static final class JwkSourceJwtDecoderBuilder {

		private static final JOSEObjectTypeVerifier<SecurityContext> NO_TYPE_VERIFIER = (header, context) -> {
		};

		private final Function<JWKSource<SecurityContext>, Set<JWSAlgorithm>> defaultAlgorithms = (source) -> Set
			.of(JWSAlgorithm.RS256);

		private final JOSEObjectTypeVerifier<SecurityContext> typeVerifier = NO_TYPE_VERIFIER;

		private final Set<SignatureAlgorithm> signatureAlgorithms = new HashSet<>();

		private Consumer<ConfigurableJWTProcessor<SecurityContext>> jwtProcessorCustomizer;

		private final JWKSource<SecurityContext> jwkSource;

		private JwkSourceJwtDecoderBuilder(JWKSource<SecurityContext> jwkSource) {
			Assert.notNull(jwkSource, "jwkSource cannot be null");
			this.jwkSource = jwkSource;
			this.jwtProcessorCustomizer = (processor) -> {
			};
		}

		/**
		 * Append the given signing
		 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target=
		 * "_blank">algorithm</a> to the set of algorithms to use.
		 * @param signatureAlgorithm the algorithm to use
		 * @return a {@link JwkSourceJwtDecoderBuilder } for further configurations
		 */
		public JwkSourceJwtDecoderBuilder jwsAlgorithm(SignatureAlgorithm signatureAlgorithm) {
			Assert.notNull(signatureAlgorithm, "signatureAlgorithm cannot be null");
			this.signatureAlgorithms.add(signatureAlgorithm);
			return this;
		}

		/**
		 * Configure the list of
		 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target=
		 * "_blank">algorithms</a> to use with the given {@link Consumer}.
		 * @param signatureAlgorithmsConsumer a {@link Consumer} for further configuring
		 * the algorithm list
		 * @return a {@link JwkSourceJwtDecoderBuilder } for further configurations
		 */
		public JwkSourceJwtDecoderBuilder jwsAlgorithms(Consumer<Set<SignatureAlgorithm>> signatureAlgorithmsConsumer) {
			Assert.notNull(signatureAlgorithmsConsumer, "signatureAlgorithmsConsumer cannot be null");
			signatureAlgorithmsConsumer.accept(this.signatureAlgorithms);
			return this;
		}

		/**
		 * Use the given {@link Consumer} to customize the {@link JWTProcessor
		 * ConfigurableJWTProcessor} before passing it to the build
		 * {@link NimbusJwtDecoder}.
		 * @param jwtProcessorCustomizer the callback used to alter the processor
		 * @return a {@link JwkSourceJwtDecoderBuilder } for further configurations
		 * @since 5.4
		 */
		public JwkSourceJwtDecoderBuilder jwtProcessorCustomizer(
				Consumer<ConfigurableJWTProcessor<SecurityContext>> jwtProcessorCustomizer) {
			Assert.notNull(jwtProcessorCustomizer, "jwtProcessorCustomizer cannot be null");
			this.jwtProcessorCustomizer = jwtProcessorCustomizer;
			return this;
		}

		JWSKeySelector<SecurityContext> jwsKeySelector(JWKSource<SecurityContext> jwkSource) {
			if (this.signatureAlgorithms.isEmpty()) {
				return new JWSVerificationKeySelector<>(this.defaultAlgorithms.apply(jwkSource), jwkSource);
			}
			Set<JWSAlgorithm> jwsAlgorithms = new HashSet<>();
			for (SignatureAlgorithm signatureAlgorithm : this.signatureAlgorithms) {
				JWSAlgorithm jwsAlgorithm = JWSAlgorithm.parse(signatureAlgorithm.getName());
				jwsAlgorithms.add(jwsAlgorithm);
			}
			return new JWSVerificationKeySelector<>(jwsAlgorithms, jwkSource);
		}

		JWTProcessor<SecurityContext> processor() {
			ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
			jwtProcessor.setJWSTypeVerifier(this.typeVerifier);
			jwtProcessor.setJWSKeySelector(jwsKeySelector(this.jwkSource));
			// Spring Security validates the claim set independent from Nimbus
			jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
			});
			this.jwtProcessorCustomizer.accept(jwtProcessor);
			return jwtProcessor;
		}

		/**
		 * Build the configured {@link NimbusJwtDecoder}.
		 * @return the configured {@link NimbusJwtDecoder}
		 */
		public NimbusJwtDecoder build() {
			return new NimbusJwtDecoder(processor());
		}

	}

}
