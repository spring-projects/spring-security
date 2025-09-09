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

package org.springframework.security.oauth2.server.authorization.authentication;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Predicate;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A {@link JwtDecoderFactory factory} that provides a {@link JwtDecoder} for the
 * specified {@link RegisteredClient} and is used for authenticating a {@link Jwt} Bearer
 * Token during OAuth 2.0 Client Authentication.
 *
 * @author Rafal Lewczuk
 * @author Joe Grandja
 * @since 7.0
 * @see JwtDecoderFactory
 * @see RegisteredClient
 * @see OAuth2TokenValidator
 * @see JwtClientAssertionAuthenticationProvider
 * @see ClientAuthenticationMethod#PRIVATE_KEY_JWT
 * @see ClientAuthenticationMethod#CLIENT_SECRET_JWT
 */
public final class JwtClientAssertionDecoderFactory implements JwtDecoderFactory<RegisteredClient> {

	/**
	 * The default {@code OAuth2TokenValidator<Jwt>} factory that validates the
	 * {@link JwtClaimNames#ISS iss}, {@link JwtClaimNames#SUB sub},
	 * {@link JwtClaimNames#AUD aud}, {@link JwtClaimNames#EXP exp} and
	 * {@link JwtClaimNames#NBF nbf} claims of the {@link Jwt} for the specified
	 * {@link RegisteredClient}.
	 */
	public static final Function<RegisteredClient, OAuth2TokenValidator<Jwt>> DEFAULT_JWT_VALIDATOR_FACTORY = defaultJwtValidatorFactory();

	private static final String JWT_CLIENT_AUTHENTICATION_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7523#section-3";

	private static final Map<JwsAlgorithm, String> JCA_ALGORITHM_MAPPINGS;

	static {
		Map<JwsAlgorithm, String> mappings = new HashMap<>();
		mappings.put(MacAlgorithm.HS256, "HmacSHA256");
		mappings.put(MacAlgorithm.HS384, "HmacSHA384");
		mappings.put(MacAlgorithm.HS512, "HmacSHA512");
		JCA_ALGORITHM_MAPPINGS = Collections.unmodifiableMap(mappings);
	}

	private static final RestTemplate restTemplate = new RestTemplate();

	static {
		SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
		requestFactory.setConnectTimeout(15_000);
		requestFactory.setReadTimeout(15_000);
		restTemplate.setRequestFactory(requestFactory);
	}

	private final Map<String, JwtDecoder> jwtDecoders = new ConcurrentHashMap<>();

	private Function<RegisteredClient, OAuth2TokenValidator<Jwt>> jwtValidatorFactory = DEFAULT_JWT_VALIDATOR_FACTORY;

	@Override
	public JwtDecoder createDecoder(RegisteredClient registeredClient) {
		Assert.notNull(registeredClient, "registeredClient cannot be null");
		return this.jwtDecoders.computeIfAbsent(registeredClient.getId(), (key) -> {
			NimbusJwtDecoder jwtDecoder = buildDecoder(registeredClient);
			jwtDecoder.setJwtValidator(this.jwtValidatorFactory.apply(registeredClient));
			return jwtDecoder;
		});
	}

	/**
	 * Sets the factory that provides an {@link OAuth2TokenValidator} for the specified
	 * {@link RegisteredClient} and is used by the {@link JwtDecoder}. The default
	 * {@code OAuth2TokenValidator<Jwt>} factory is
	 * {@link #DEFAULT_JWT_VALIDATOR_FACTORY}.
	 * @param jwtValidatorFactory the factory that provides an
	 * {@link OAuth2TokenValidator} for the specified {@link RegisteredClient}
	 */
	public void setJwtValidatorFactory(Function<RegisteredClient, OAuth2TokenValidator<Jwt>> jwtValidatorFactory) {
		Assert.notNull(jwtValidatorFactory, "jwtValidatorFactory cannot be null");
		this.jwtValidatorFactory = jwtValidatorFactory;
	}

	private static NimbusJwtDecoder buildDecoder(RegisteredClient registeredClient) {
		JwsAlgorithm jwsAlgorithm = registeredClient.getClientSettings()
			.getTokenEndpointAuthenticationSigningAlgorithm();
		if (jwsAlgorithm instanceof SignatureAlgorithm) {
			String jwkSetUrl = registeredClient.getClientSettings().getJwkSetUrl();
			if (!StringUtils.hasText(jwkSetUrl)) {
				OAuth2Error oauth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
						"Failed to find a Signature Verifier for Client: '" + registeredClient.getId()
								+ "'. Check to ensure you have configured the JWK Set URL.",
						JWT_CLIENT_AUTHENTICATION_ERROR_URI);
				throw new OAuth2AuthenticationException(oauth2Error);
			}
			return NimbusJwtDecoder.withJwkSetUri(jwkSetUrl)
				.jwsAlgorithm((SignatureAlgorithm) jwsAlgorithm)
				.restOperations(restTemplate)
				.build();
		}
		if (jwsAlgorithm instanceof MacAlgorithm) {
			String clientSecret = registeredClient.getClientSecret();
			if (!StringUtils.hasText(clientSecret)) {
				OAuth2Error oauth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
						"Failed to find a Signature Verifier for Client: '" + registeredClient.getId()
								+ "'. Check to ensure you have configured the client secret.",
						JWT_CLIENT_AUTHENTICATION_ERROR_URI);
				throw new OAuth2AuthenticationException(oauth2Error);
			}
			SecretKeySpec secretKeySpec = new SecretKeySpec(clientSecret.getBytes(StandardCharsets.UTF_8),
					JCA_ALGORITHM_MAPPINGS.get(jwsAlgorithm));
			return NimbusJwtDecoder.withSecretKey(secretKeySpec).macAlgorithm((MacAlgorithm) jwsAlgorithm).build();
		}
		OAuth2Error oauth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
				"Failed to find a Signature Verifier for Client: '" + registeredClient.getId()
						+ "'. Check to ensure you have configured a valid JWS Algorithm: '" + jwsAlgorithm + "'.",
				JWT_CLIENT_AUTHENTICATION_ERROR_URI);
		throw new OAuth2AuthenticationException(oauth2Error);
	}

	private static Function<RegisteredClient, OAuth2TokenValidator<Jwt>> defaultJwtValidatorFactory() {
		return (registeredClient) -> {
			String clientId = registeredClient.getClientId();
			return new DelegatingOAuth2TokenValidator<>(new JwtClaimValidator<>(JwtClaimNames.ISS, clientId::equals),
					new JwtClaimValidator<>(JwtClaimNames.SUB, clientId::equals),
					new JwtClaimValidator<>(JwtClaimNames.AUD, containsAudience()),
					new JwtClaimValidator<>(JwtClaimNames.EXP, Objects::nonNull), new JwtTimestampValidator());
		};
	}

	private static Predicate<List<String>> containsAudience() {
		return (audienceClaim) -> {
			if (CollectionUtils.isEmpty(audienceClaim)) {
				return false;
			}
			List<String> audienceList = getAudience();
			for (String audience : audienceClaim) {
				if (audienceList.contains(audience)) {
					return true;
				}
			}
			return false;
		};
	}

	private static List<String> getAudience() {
		AuthorizationServerContext authorizationServerContext = AuthorizationServerContextHolder.getContext();
		if (!StringUtils.hasText(authorizationServerContext.getIssuer())) {
			return Collections.emptyList();
		}

		AuthorizationServerSettings authorizationServerSettings = authorizationServerContext
			.getAuthorizationServerSettings();
		List<String> audience = new ArrayList<>();
		audience.add(authorizationServerContext.getIssuer());
		audience.add(asUrl(authorizationServerContext.getIssuer(), authorizationServerSettings.getTokenEndpoint()));
		audience.add(asUrl(authorizationServerContext.getIssuer(),
				authorizationServerSettings.getTokenIntrospectionEndpoint()));
		audience.add(asUrl(authorizationServerContext.getIssuer(),
				authorizationServerSettings.getTokenRevocationEndpoint()));
		audience.add(asUrl(authorizationServerContext.getIssuer(),
				authorizationServerSettings.getPushedAuthorizationRequestEndpoint()));
		return audience;
	}

	private static String asUrl(String issuer, String endpoint) {
		return UriComponentsBuilder.fromUriString(issuer).path(endpoint).build().toUriString();
	}

}
