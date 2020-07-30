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

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import javax.crypto.SecretKey;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
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
 * A low-level Nimbus implementation of {@link JwtDecoder} which takes a raw Nimbus configuration.
 *
 * @author Josh Cummings
 * @author Joe Grandja
 * @since 5.2
 */
public final class NimbusJwtDecoder implements JwtDecoder {
	private static final String DECODING_ERROR_MESSAGE_TEMPLATE =
			"An error occurred while attempting to decode the Jwt: %s";

	private final JWTProcessor<SecurityContext> jwtProcessor;

	private Converter<Map<String, Object>, Map<String, Object>> claimSetConverter =
			MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());
	private OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators.createDefault();

	/**
	 * Configures a {@link NimbusJwtDecoder} with the given parameters
	 *
	 * @param jwtProcessor - the {@link JWTProcessor} to use
	 */
	public NimbusJwtDecoder(JWTProcessor<SecurityContext> jwtProcessor) {
		Assert.notNull(jwtProcessor, "jwtProcessor cannot be null");
		this.jwtProcessor = jwtProcessor;
	}

	/**
	 * Use this {@link Jwt} Validator
	 *
	 * @param jwtValidator - the Jwt Validator to use
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

	/**
	 * Decode and validate the JWT from its compact claims representation format
	 *
	 * @param token the JWT value
	 * @return a validated {@link Jwt}
	 * @throws JwtException
	 */
	@Override
	public Jwt decode(String token) throws JwtException {
		JWT jwt = parse(token);
		if (jwt instanceof PlainJWT) {
			throw new JwtException("Unsupported algorithm of " + jwt.getHeader().getAlgorithm());
		}
		Jwt createdJwt = createJwt(token, jwt);
		return validateJwt(createdJwt);
	}

	private JWT parse(String token) {
		try {
			return JWTParser.parse(token);
		} catch (Exception ex) {
			throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
		}
	}

	private Jwt createJwt(String token, JWT parsedJwt) {
		try {
			// Verify the signature
			JWTClaimsSet jwtClaimsSet = this.jwtProcessor.process(parsedJwt, null);

			Map<String, Object> headers = new LinkedHashMap<>(parsedJwt.getHeader().toJSONObject());
			Map<String, Object> claims = this.claimSetConverter.convert(jwtClaimsSet.getClaims());

			return Jwt.withTokenValue(token)
					.headers(h -> h.putAll(headers))
					.claims(c -> c.putAll(claims))
					.build();
		} catch (RemoteKeySourceException ex) {
			if (ex.getCause() instanceof ParseException) {
				throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, "Malformed Jwk set"));
			} else {
				throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
			}
		} catch (Exception ex) {
			if (ex.getCause() instanceof ParseException) {
				throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, "Malformed payload"));
			} else {
				throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
			}
		}
	}

	private Jwt validateJwt(Jwt jwt){
		OAuth2TokenValidatorResult result = this.jwtValidator.validate(jwt);
		if (result.hasErrors()) {
			Collection<OAuth2Error> errors = result.getErrors();
			String validationErrorString = "Unable to validate Jwt";
			for (OAuth2Error oAuth2Error : errors) {
				if (!StringUtils.isEmpty(oAuth2Error.getDescription())) {
					validationErrorString = String.format(
							DECODING_ERROR_MESSAGE_TEMPLATE, oAuth2Error.getDescription());
					break;
				}
			}
			throw new JwtValidationException(
					validationErrorString,
					result.getErrors());
		}

		return jwt;
	}

	/**
	 * Use the given
	 * <a href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</a> uri.
	 *
	 * @param jwkSetUri the JWK Set uri to use
	 * @return a {@link JwkSetUriJwtDecoderBuilder} for further configurations
	 */
	public static JwkSetUriJwtDecoderBuilder withJwkSetUri(String jwkSetUri) {
		return new JwkSetUriJwtDecoderBuilder(jwkSetUri);
	}

	/**
	 * Use the given public key to validate JWTs
	 *
	 * @param key the public key to use
	 * @return a {@link PublicKeyJwtDecoderBuilder} for further configurations
	 */
	public static PublicKeyJwtDecoderBuilder withPublicKey(RSAPublicKey key) {
		return new PublicKeyJwtDecoderBuilder(key);
	}

	/**
	 * Use the given {@code SecretKey} to validate the MAC on a JSON Web Signature (JWS).
	 *
	 * @param secretKey the {@code SecretKey} used to validate the MAC
	 * @return a {@link SecretKeyJwtDecoderBuilder} for further configurations
	 */
	public static SecretKeyJwtDecoderBuilder withSecretKey(SecretKey secretKey) {
		return new SecretKeyJwtDecoderBuilder(secretKey);
	}

	/**
	 * A builder for creating {@link NimbusJwtDecoder} instances based on a
	 * <a target="_blank" href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</a> uri.
	 */
	public static final class JwkSetUriJwtDecoderBuilder {
		private String jwkSetUri;
		private Set<SignatureAlgorithm> signatureAlgorithms = new HashSet<>();
		private RestOperations restOperations = new RestTemplate();

		private JwkSetUriJwtDecoderBuilder(String jwkSetUri) {
			Assert.hasText(jwkSetUri, "jwkSetUri cannot be empty");
			this.jwkSetUri = jwkSetUri;
		}

		/**
		 * Append the given signing
		 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target="_blank">algorithm</a>
		 * to the set of algorithms to use.
		 *
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
		 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target="_blank">algorithms</a>
		 * to use with the given {@link Consumer}.
		 *
		 * @param signatureAlgorithmsConsumer a {@link Consumer} for further configuring the algorithm list
		 * @return a {@link JwkSetUriJwtDecoderBuilder} for further configurations
		 */
		public JwkSetUriJwtDecoderBuilder jwsAlgorithms(Consumer<Set<SignatureAlgorithm>> signatureAlgorithmsConsumer) {
			Assert.notNull(signatureAlgorithmsConsumer, "signatureAlgorithmsConsumer cannot be null");
			signatureAlgorithmsConsumer.accept(this.signatureAlgorithms);
			return this;
		}

		/**
		 * Use the given {@link RestOperations} to coordinate with the authorization servers indicated in the
		 * <a href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</a> uri
		 * as well as the
		 * <a href="https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a>.
		 *
		 * @param restOperations
		 * @return
		 */
		public JwkSetUriJwtDecoderBuilder restOperations(RestOperations restOperations) {
			Assert.notNull(restOperations, "restOperations cannot be null");
			this.restOperations = restOperations;
			return this;
		}

		JWSKeySelector<SecurityContext> jwsKeySelector(JWKSource<SecurityContext> jwkSource) {
			if (this.signatureAlgorithms.isEmpty()) {
				return new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);
			} else if (this.signatureAlgorithms.size() == 1) {
				JWSAlgorithm jwsAlgorithm = JWSAlgorithm.parse(this.signatureAlgorithms.iterator().next().getName());
				return new JWSVerificationKeySelector<>(jwsAlgorithm, jwkSource);
			} else {
				Map<JWSAlgorithm, JWSKeySelector<SecurityContext>> jwsKeySelectors = new HashMap<>();
				for (SignatureAlgorithm signatureAlgorithm : this.signatureAlgorithms) {
					JWSAlgorithm jwsAlg = JWSAlgorithm.parse(signatureAlgorithm.getName());
					jwsKeySelectors.put(jwsAlg, new JWSVerificationKeySelector<>(jwsAlg, jwkSource));
				}
				return new JWSAlgorithmMapJWSKeySelector<>(jwsKeySelectors);
			}
		}

		JWTProcessor<SecurityContext> processor() {
			ResourceRetriever jwkSetRetriever = new RestOperationsResourceRetriever(this.restOperations);
			JWKSource<SecurityContext> jwkSource = new RemoteJWKSet<>(toURL(this.jwkSetUri), jwkSetRetriever);
			ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
			jwtProcessor.setJWSKeySelector(jwsKeySelector(jwkSource));

			// Spring Security validates the claim set independent from Nimbus
			jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> { });

			return jwtProcessor;
		}

		/**
		 * Build the configured {@link NimbusJwtDecoder}.
		 *
		 * @return the configured {@link NimbusJwtDecoder}
		 */
		public NimbusJwtDecoder build() {
			return new NimbusJwtDecoder(processor());
		}

		private static URL toURL(String url) {
			try {
				return new URL(url);
			} catch (MalformedURLException ex) {
				throw new IllegalArgumentException("Invalid JWK Set URL \"" + url + "\" : " + ex.getMessage(), ex);
			}
		}

		private static class RestOperationsResourceRetriever implements ResourceRetriever {
			private static final MediaType APPLICATION_JWK_SET_JSON = new MediaType("application", "jwk-set+json");
			private final RestOperations restOperations;

			RestOperationsResourceRetriever(RestOperations restOperations) {
				Assert.notNull(restOperations, "restOperations cannot be null");
				this.restOperations = restOperations;
			}

			@Override
			public Resource retrieveResource(URL url) throws IOException {
				HttpHeaders headers = new HttpHeaders();
				headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON, APPLICATION_JWK_SET_JSON));

				ResponseEntity<String> response;
				try {
					RequestEntity<Void> request = new RequestEntity<>(headers, HttpMethod.GET, url.toURI());
					response = this.restOperations.exchange(request, String.class);
				} catch (Exception ex) {
					throw new IOException(ex);
				}

				if (response.getStatusCodeValue() != 200) {
					throw new IOException(response.toString());
				}

				return new Resource(response.getBody(), "UTF-8");
			}
		}
	}

	/**
	 * A builder for creating {@link NimbusJwtDecoder} instances based on a public key.
	 */
	public static final class PublicKeyJwtDecoderBuilder {
		private JWSAlgorithm jwsAlgorithm;
		private RSAPublicKey key;

		private PublicKeyJwtDecoderBuilder(RSAPublicKey key) {
			Assert.notNull(key, "key cannot be null");
			this.jwsAlgorithm = JWSAlgorithm.RS256;
			this.key = key;
		}

		/**
		 * Use the given signing
		 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target="_blank">algorithm</a>.
		 *
		 * The value should be one of
		 * <a href="https://tools.ietf.org/html/rfc7518#section-3.3" target="_blank">RS256, RS384, or RS512</a>.
		 *
		 * @param signatureAlgorithm the algorithm to use
		 * @return a {@link PublicKeyJwtDecoderBuilder} for further configurations
		 */
		public PublicKeyJwtDecoderBuilder signatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
			Assert.notNull(signatureAlgorithm, "signatureAlgorithm cannot be null");
			this.jwsAlgorithm = JWSAlgorithm.parse(signatureAlgorithm.getName());
			return this;
		}

		JWTProcessor<SecurityContext> processor() {
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

			return jwtProcessor;
		}

		/**
		 * Build the configured {@link NimbusJwtDecoder}.
		 *
		 * @return the configured {@link NimbusJwtDecoder}
		 */
		public NimbusJwtDecoder build() {
			return new NimbusJwtDecoder(processor());
		}
	}

	/**
	 * A builder for creating {@link NimbusJwtDecoder} instances based on a {@code SecretKey}.
	 */
	public static final class SecretKeyJwtDecoderBuilder {
		private final SecretKey secretKey;
		private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS256;

		private SecretKeyJwtDecoderBuilder(SecretKey secretKey) {
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
		 * @return a {@link SecretKeyJwtDecoderBuilder} for further configurations
		 */
		public SecretKeyJwtDecoderBuilder macAlgorithm(MacAlgorithm macAlgorithm) {
			Assert.notNull(macAlgorithm, "macAlgorithm cannot be null");
			this.jwsAlgorithm = JWSAlgorithm.parse(macAlgorithm.getName());
			return this;
		}

		/**
		 * Build the configured {@link NimbusJwtDecoder}.
		 *
		 * @return the configured {@link NimbusJwtDecoder}
		 */
		public NimbusJwtDecoder build() {
			return new NimbusJwtDecoder(processor());
		}

		JWTProcessor<SecurityContext> processor() {
			JWSKeySelector<SecurityContext> jwsKeySelector =
					new SingleKeyJWSKeySelector<>(this.jwsAlgorithm, this.secretKey);
			DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
			jwtProcessor.setJWSKeySelector(jwsKeySelector);

			// Spring Security validates the claim set independent from Nimbus
			jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> { });

			return jwtProcessor;
		}
	}
}
