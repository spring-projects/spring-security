/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.oauth2.client.endpoint;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * A {@link Converter} that customizes the OAuth 2.0 Access Token Request parameters by
 * adding a signed JSON Web Token (JWS) to be used for client authentication at the
 * Authorization Server's Token Endpoint. The private/secret key used for signing the JWS
 * is supplied by the {@code com.nimbusds.jose.jwk.JWK} resolver provided via the
 * constructor.
 *
 * <p>
 * <b>NOTE:</b> This implementation uses the Nimbus JOSE + JWT SDK.
 *
 * @param <T> the type of {@link AbstractOAuth2AuthorizationGrantRequest}
 * @author Joe Grandja
 * @since 5.5
 * @see Converter
 * @see com.nimbusds.jose.jwk.JWK
 * @see JwtCustomizer
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7523#section-2.2">2.2
 * Using JWTs for Client Authentication</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7521#section-4.2">4.2
 * Using Assertions for Client Authentication</a>
 * @see <a target="_blank" href="https://connect2id.com/products/nimbus-jose-jwt">Nimbus
 * JOSE + JWT SDK</a>
 */
public final class NimbusJwtClientAuthenticationParametersConverter<T extends AbstractOAuth2AuthorizationGrantRequest>
		implements Converter<T, MultiValueMap<String, String>> {

	private static final String INVALID_KEY_ERROR_CODE = "invalid_key";

	private static final String INVALID_ALGORITHM_ERROR_CODE = "invalid_algorithm";

	private static final String CLIENT_ASSERTION_TYPE_VALUE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

	private final Function<ClientRegistration, JWK> jwkResolver;

	private final Map<String, NimbusJwsEncoder> jwtEncoders = new ConcurrentHashMap<>();

	private JwtCustomizer<T> jwtCustomizer = (request, headers, claims) -> {
	};

	/**
	 * Constructs a {@code NimbusJwtClientAuthenticationCustomizer} using the provided
	 * parameters.
	 * @param jwkResolver the resolver that provides the {@code com.nimbusds.jose.jwk.JWK}
	 * associated to the {@link ClientRegistration client}
	 */
	public NimbusJwtClientAuthenticationParametersConverter(Function<ClientRegistration, JWK> jwkResolver) {
		Assert.notNull(jwkResolver, "jwkResolver cannot be null");
		this.jwkResolver = jwkResolver;
	}

	@Override
	public MultiValueMap<String, String> convert(T authorizationGrantRequest) {
		Assert.notNull(authorizationGrantRequest, "authorizationGrantRequest cannot be null");

		ClientRegistration clientRegistration = authorizationGrantRequest.getClientRegistration();
		if (!ClientAuthenticationMethod.PRIVATE_KEY_JWT.equals(clientRegistration.getClientAuthenticationMethod())
				&& !ClientAuthenticationMethod.CLIENT_SECRET_JWT
						.equals(clientRegistration.getClientAuthenticationMethod())) {
			return null;
		}

		JWK jwk = this.jwkResolver.apply(clientRegistration);
		if (jwk == null) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_KEY_ERROR_CODE,
					"Failed to resolve JWK signing key for client registration '"
							+ clientRegistration.getRegistrationId() + "'.",
					null);
			throw new OAuth2AuthorizationException(oauth2Error);
		}

		JwsAlgorithm jwsAlgorithm = resolveAlgorithm(jwk);
		if (jwsAlgorithm == null) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_ALGORITHM_ERROR_CODE,
					"Unable to resolve JWS (signing) algorithm from JWK associated to client registration '"
							+ clientRegistration.getRegistrationId() + "'.",
					null);
			throw new OAuth2AuthorizationException(oauth2Error);
		}

		JoseHeader.Builder headersBuilder = JoseHeader.withAlgorithm(jwsAlgorithm);

		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(Duration.ofSeconds(60));

		// @formatter:off
		JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder()
				.issuer(clientRegistration.getClientId())
				.subject(clientRegistration.getClientId())
				.audience(Collections.singletonList(clientRegistration.getProviderDetails().getTokenUri()))
				.id(UUID.randomUUID().toString())
				.issuedAt(issuedAt)
				.expiresAt(expiresAt);
		// @formatter:on

		this.jwtCustomizer.customize(authorizationGrantRequest, headersBuilder.headers, claimsBuilder.claims);

		JoseHeader joseHeader = headersBuilder.build();
		JwtClaimsSet jwtClaimsSet = claimsBuilder.build();

		NimbusJwsEncoder jwsEncoder = this.jwtEncoders.computeIfAbsent(clientRegistration.getRegistrationId(),
				(clientRegistrationId) -> {
					JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
					return new NimbusJwsEncoder(jwkSource);
				});

		Jwt jws = jwsEncoder.encode(joseHeader, jwtClaimsSet);

		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, CLIENT_ASSERTION_TYPE_VALUE);
		parameters.set(OAuth2ParameterNames.CLIENT_ASSERTION, jws.getTokenValue());

		return parameters;
	}

	/**
	 * Sets the {@link JwtCustomizer} to be provided the opportunity to customize the
	 * {@link Jwt} headers and/or claims.
	 * @param jwtCustomizer the {@link JwtCustomizer} to be provided the opportunity to
	 * customize the {@link Jwt} headers and/or claims
	 */
	public void setJwtCustomizer(JwtCustomizer<T> jwtCustomizer) {
		Assert.notNull(jwtCustomizer, "jwtCustomizer cannot be null");
		this.jwtCustomizer = jwtCustomizer;
	}

	private static JwsAlgorithm resolveAlgorithm(JWK jwk) {
		JwsAlgorithm jwsAlgorithm = null;

		if (jwk.getAlgorithm() != null) {
			jwsAlgorithm = SignatureAlgorithm.from(jwk.getAlgorithm().getName());
			if (jwsAlgorithm == null) {
				jwsAlgorithm = MacAlgorithm.from(jwk.getAlgorithm().getName());
			}
		}

		if (jwsAlgorithm == null) {
			if (KeyType.RSA.equals(jwk.getKeyType())) {
				jwsAlgorithm = SignatureAlgorithm.RS256;
			}
			else if (KeyType.EC.equals(jwk.getKeyType())) {
				jwsAlgorithm = SignatureAlgorithm.ES256;
			}
			else if (KeyType.OCT.equals(jwk.getKeyType())) {
				jwsAlgorithm = MacAlgorithm.HS256;
			}
		}

		return jwsAlgorithm;
	}

	/**
	 * Implementations of this interface are provided the opportunity to customize the
	 * {@link Jwt} headers and/or claims.
	 *
	 * @param <T> the type of {@link AbstractOAuth2AuthorizationGrantRequest}
	 */
	@FunctionalInterface
	interface JwtCustomizer<T extends AbstractOAuth2AuthorizationGrantRequest> {

		/**
		 * Customize the {@link Jwt} headers and/or claims.
		 * @param authorizationGrantRequest the authorization grant request
		 * @param headers the headers
		 * @param claims the claims
		 */
		void customize(T authorizationGrantRequest, Map<String, Object> headers, Map<String, Object> claims);

	}

}
