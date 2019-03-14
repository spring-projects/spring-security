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
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import static org.springframework.security.oauth2.jwt.JwtProcessors.withJwkSetUri;

/**
 * A {@link JwtDecoderFactory factory} that provides a {@link JwtDecoder}
 * used for {@link OidcIdToken} signature verification.
 * The provided {@link JwtDecoder} is associated to a specific {@link ClientRegistration}.
 *
 * @author Joe Grandja
 * @author Rafael Dominguez
 * @since 5.2
 * @see JwtDecoderFactory
 * @see ClientRegistration
 * @see OidcIdToken
 */
public final class OidcIdTokenDecoderFactory implements JwtDecoderFactory<ClientRegistration> {
	private static final String MISSING_SIGNATURE_VERIFIER_ERROR_CODE = "missing_signature_verifier";
	private final Map<String, JwtDecoder> jwtDecoders = new ConcurrentHashMap<>();
	private Function<ClientRegistration, OAuth2TokenValidator<Jwt>> jwtValidatorFactory = OidcIdTokenValidator::new;

	@Override
	public JwtDecoder createDecoder(ClientRegistration clientRegistration) {
		Assert.notNull(clientRegistration, "clientRegistration cannot be null");
		return this.jwtDecoders.computeIfAbsent(clientRegistration.getRegistrationId(), key -> {
			if (!StringUtils.hasText(clientRegistration.getProviderDetails().getJwkSetUri())) {
				OAuth2Error oauth2Error = new OAuth2Error(
						MISSING_SIGNATURE_VERIFIER_ERROR_CODE,
						"Failed to find a Signature Verifier for Client Registration: '" +
								clientRegistration.getRegistrationId() +
								"'. Check to ensure you have configured the JwkSet URI.",
						null
				);
				throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
			}
			String jwkSetUri = clientRegistration.getProviderDetails().getJwkSetUri();
			NimbusJwtDecoder jwtDecoder = new NimbusJwtDecoder(withJwkSetUri(jwkSetUri).build());
			OAuth2TokenValidator<Jwt> jwtValidator = this.jwtValidatorFactory.apply(clientRegistration);
			jwtDecoder.setJwtValidator(jwtValidator);
			return jwtDecoder;
		});
	}

	/**
	 * Sets the factory that provides an {@link OAuth2TokenValidator}, which is used by the {@link JwtDecoder}.
	 * The default is {@link OidcIdTokenValidator}.
	 *
	 * @param jwtValidatorFactory the factory that provides an {@link OAuth2TokenValidator}
	 */
	public final void setJwtValidatorFactory(Function<ClientRegistration, OAuth2TokenValidator<Jwt>> jwtValidatorFactory) {
		Assert.notNull(jwtValidatorFactory, "jwtValidatorFactory cannot be null");
		this.jwtValidatorFactory = jwtValidatorFactory;
	}
}
