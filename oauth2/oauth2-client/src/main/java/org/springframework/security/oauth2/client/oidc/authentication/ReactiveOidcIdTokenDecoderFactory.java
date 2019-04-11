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
package org.springframework.security.oauth2.client.oidc.authentication;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoderFactory;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import static org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder.withJwkSetUri;
import static org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder.withSecretKey;

/**
 * A {@link ReactiveJwtDecoderFactory factory} that provides a {@link ReactiveJwtDecoder}
 * used for {@link OidcIdToken} signature verification.
 * The provided {@link ReactiveJwtDecoder} is associated to a specific {@link ClientRegistration}.
 *
 * @author Joe Grandja
 * @author Rafael Dominguez
 * @since 5.2
 * @see ReactiveJwtDecoderFactory
 * @see ClientRegistration
 * @see OidcIdToken
 */
public final class ReactiveOidcIdTokenDecoderFactory implements ReactiveJwtDecoderFactory<ClientRegistration> {
	private static final String MISSING_SIGNATURE_VERIFIER_ERROR_CODE = "missing_signature_verifier";
	private static Map<JwsAlgorithm, String> jcaAlgorithmMappings = new HashMap<JwsAlgorithm, String>() {
		{
			put(MacAlgorithm.HS256, "HmacSHA256");
			put(MacAlgorithm.HS384, "HmacSHA384");
			put(MacAlgorithm.HS512, "HmacSHA512");
		}
	};
	private final Map<String, ReactiveJwtDecoder> jwtDecoders = new ConcurrentHashMap<>();
	private Function<ClientRegistration, OAuth2TokenValidator<Jwt>> jwtValidatorFactory = OidcIdTokenValidator::new;
	private Function<ClientRegistration, JwsAlgorithm> jwsAlgorithmResolver = clientRegistration -> SignatureAlgorithm.RS256;

	@Override
	public ReactiveJwtDecoder createDecoder(ClientRegistration clientRegistration) {
		Assert.notNull(clientRegistration, "clientRegistration cannot be null");
		return this.jwtDecoders.computeIfAbsent(clientRegistration.getRegistrationId(), key -> {
			NimbusReactiveJwtDecoder jwtDecoder = buildDecoder(clientRegistration);
			OAuth2TokenValidator<Jwt> jwtValidator = this.jwtValidatorFactory.apply(clientRegistration);
			jwtDecoder.setJwtValidator(jwtValidator);
			return jwtDecoder;
		});
	}

	private NimbusReactiveJwtDecoder buildDecoder(ClientRegistration clientRegistration) {
		JwsAlgorithm jwsAlgorithm = this.jwsAlgorithmResolver.apply(clientRegistration);
		if (jwsAlgorithm != null && SignatureAlgorithm.class.isAssignableFrom(jwsAlgorithm.getClass())) {
			// https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
			//
			// 6. If the ID Token is received via direct communication between the Client
			// and the Token Endpoint (which it is in this flow),
			// the TLS server validation MAY be used to validate the issuer in place of checking the token signature.
			// The Client MUST validate the signature of all other ID Tokens according to JWS [JWS]
			// using the algorithm specified in the JWT alg Header Parameter.
			// The Client MUST use the keys provided by the Issuer.
			//
			// 7. The alg value SHOULD be the default of RS256 or the algorithm sent by the Client
			// in the id_token_signed_response_alg parameter during Registration.

			String jwkSetUri = clientRegistration.getProviderDetails().getJwkSetUri();
			if (!StringUtils.hasText(jwkSetUri)) {
				OAuth2Error oauth2Error = new OAuth2Error(
						MISSING_SIGNATURE_VERIFIER_ERROR_CODE,
						"Failed to find a Signature Verifier for Client Registration: '" +
								clientRegistration.getRegistrationId() +
								"'. Check to ensure you have configured the JwkSet URI.",
						null
				);
				throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
			}
			return withJwkSetUri(jwkSetUri).jwsAlgorithm(jwsAlgorithm).build();
		} else if (jwsAlgorithm != null && MacAlgorithm.class.isAssignableFrom(jwsAlgorithm.getClass())) {
			// https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
			//
			// 8. If the JWT alg Header Parameter uses a MAC based algorithm such as HS256, HS384, or HS512,
			// the octets of the UTF-8 representation of the client_secret
			// corresponding to the client_id contained in the aud (audience) Claim
			// are used as the key to validate the signature.
			// For MAC based algorithms, the behavior is unspecified if the aud is multi-valued or
			// if an azp value is present that is different than the aud value.

			String clientSecret = clientRegistration.getClientSecret();
			if (!StringUtils.hasText(clientSecret)) {
				OAuth2Error oauth2Error = new OAuth2Error(
						MISSING_SIGNATURE_VERIFIER_ERROR_CODE,
						"Failed to find a Signature Verifier for Client Registration: '" +
								clientRegistration.getRegistrationId() +
								"'. Check to ensure you have configured the client secret.",
						null
				);
				throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
			}
			SecretKeySpec secretKeySpec = new SecretKeySpec(
					clientSecret.getBytes(StandardCharsets.UTF_8), jcaAlgorithmMappings.get(jwsAlgorithm));
			return withSecretKey(secretKeySpec).macAlgorithm((MacAlgorithm) jwsAlgorithm).build();
		}

		OAuth2Error oauth2Error = new OAuth2Error(
				MISSING_SIGNATURE_VERIFIER_ERROR_CODE,
				"Failed to find a Signature Verifier for Client Registration: '" +
						clientRegistration.getRegistrationId() +
						"'. Check to ensure you have configured a valid JWS Algorithm: '" +
						jwsAlgorithm + "'",
				null
		);
		throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
	}

	/**
	 * Sets the factory that provides an {@link OAuth2TokenValidator}, which is used by the {@link ReactiveJwtDecoder}.
	 * The default is {@link OidcIdTokenValidator}.
	 *
	 * @param jwtValidatorFactory the factory that provides an {@link OAuth2TokenValidator}
	 */
	public final void setJwtValidatorFactory(Function<ClientRegistration, OAuth2TokenValidator<Jwt>> jwtValidatorFactory) {
		Assert.notNull(jwtValidatorFactory, "jwtValidatorFactory cannot be null");
		this.jwtValidatorFactory = jwtValidatorFactory;
	}

	/**
	 * Sets the resolver that provides the expected {@link JwsAlgorithm JWS algorithm}
	 * used for the signature or MAC on the {@link OidcIdToken ID Token}.
	 * The default resolves to {@link SignatureAlgorithm#RS256 RS256} for all {@link ClientRegistration clients}.
	 *
	 * @param jwsAlgorithmResolver the resolver that provides the expected {@link JwsAlgorithm JWS algorithm}
	 *                             for a specific {@link ClientRegistration client}
	 */
	public final void setJwsAlgorithmResolver(Function<ClientRegistration, JwsAlgorithm> jwsAlgorithmResolver) {
		Assert.notNull(jwsAlgorithmResolver, "jwsAlgorithmResolver cannot be null");
		this.jwsAlgorithmResolver = jwsAlgorithmResolver;
	}
}
