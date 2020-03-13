/*
 * Copyright 2002-2020 the original author or authors.
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

import com.nimbusds.jose.JOSEException;
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
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.*;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.util.Assert;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * A low-level Nimbus implementation of {@link JwtDecoder} which takes a raw Nimbus configuration.
 *
 * @author Josh Cummings
 * @author Joe Grandja
 * @author Nick Hitchan
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
			throw new BadJwtException("Unsupported algorithm of " + jwt.getHeader().getAlgorithm());
		}
		Jwt createdJwt = createJwt(token, jwt);
		return validateJwt(createdJwt);
	}

	private JWT parse(String token) {
		try {
			return JWTParser.parse(token);
		} catch (Exception ex) {
			throw new BadJwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
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
		} catch (JOSEException ex) {
			throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
		} catch (Exception ex) {
			if (ex.getCause() instanceof ParseException) {
				throw new BadJwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, "Malformed payload"));
			} else {
				throw new BadJwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
			}
		}
	}

	private Jwt validateJwt(Jwt jwt){
		OAuth2TokenValidatorResult result = this.jwtValidator.validate(jwt);
		if (result.hasErrors()) {
			String description = result.getErrors().iterator().next().getDescription();
			throw new JwtValidationException(
					String.format(DECODING_ERROR_MESSAGE_TEMPLATE, description),
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

		private static final Log log = LogFactory
				.getLog(JwkSetUriJwtDecoderBuilder.class);

		private static final String KEYS = "keys";

		private static final String ALGORITHM = "alg";

		private static final ParameterizedTypeReference<Map<String, Object>> typeReference =
				new ParameterizedTypeReference<Map<String, Object>>() {};

		private JSONParser jsonParser = new JSONParser(JSONParser.MODE_STRICTEST);

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
			Set<SignatureAlgorithm> jwkAlgorithms = new HashSet<>();
			if (this.signatureAlgorithms.isEmpty()) {
				jwkAlgorithms.add(SignatureAlgorithm.RS256);
			} else {
				jwkAlgorithms.addAll(this.signatureAlgorithms);
			}
			jwkAlgorithms.addAll(fetchJwkAlgorithms());
			return new JWSAlgorithmMapJWSKeySelector<>(jwkAlgorithms.stream()
					.map(algorithm -> JWSAlgorithm.parse(algorithm.getName()))
					.collect(Collectors.toMap(algorithm -> algorithm,
							algorithm -> new JWSVerificationKeySelector<>(JWSAlgorithm.parse(algorithm.getName()), jwkSource))));
		}

		Set<SignatureAlgorithm> fetchJwkAlgorithms() {
			try {

				ResponseEntity<String> response = restOperations.exchange(RequestEntity.get(URI.create(jwkSetUri))
						.build(), String.class);
				String body = response.getBody();

				if (body == null) {
					return Collections.emptySet();
				}

				JSONObject root = (JSONObject) jsonParser.parse(body);
				JSONArray keys = (JSONArray) root.get(KEYS);
				return keys == null ? Collections.emptySet() : keys.stream()
						.map(element -> {
							JSONObject key = (JSONObject) element;
							return SignatureAlgorithm.from(key.getAsString(ALGORITHM));
						}).filter(Objects::nonNull)
						.collect(Collectors.toSet());
			} catch (Exception ex) {
				log.warn("An error occurred while attempting to discover JWK algorithm support from the JWK Set resource.");
			}

			return Collections.emptySet();
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
