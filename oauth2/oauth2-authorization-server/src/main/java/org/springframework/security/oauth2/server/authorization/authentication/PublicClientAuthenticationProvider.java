/*
 * Copyright 2020-2022 the original author or authors.
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation used for OAuth 2.0 Public Client
 * Authentication, which authenticates the {@link PkceParameterNames#CODE_VERIFIER
 * code_verifier} parameter.
 *
 * @author Joe Grandja
 * @since 0.2.3
 * @see AuthenticationProvider
 * @see OAuth2ClientAuthenticationToken
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 */
public final class PublicClientAuthenticationProvider implements AuthenticationProvider {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1";

	private final Log logger = LogFactory.getLog(getClass());

	private final RegisteredClientRepository registeredClientRepository;

	private final CodeVerifierAuthenticator codeVerifierAuthenticator;

	/**
	 * Constructs a {@code PublicClientAuthenticationProvider} using the provided
	 * parameters.
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 */
	public PublicClientAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.codeVerifierAuthenticator = new CodeVerifierAuthenticator(authorizationService);
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2ClientAuthenticationToken clientAuthentication = (OAuth2ClientAuthenticationToken) authentication;

		if (!ClientAuthenticationMethod.NONE.equals(clientAuthentication.getClientAuthenticationMethod())) {
			return null;
		}

		String clientId = clientAuthentication.getPrincipal().toString();
		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
		if (registeredClient == null) {
			throwInvalidClient(OAuth2ParameterNames.CLIENT_ID);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved registered client");
		}

		if (!registeredClient.getClientAuthenticationMethods()
			.contains(clientAuthentication.getClientAuthenticationMethod())) {
			throwInvalidClient("authentication_method");
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Validated client authentication parameters");
		}

		// Validate the "code_verifier" parameter for the public client
		this.codeVerifierAuthenticator.authenticateRequired(clientAuthentication, registeredClient);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Authenticated public client");
		}

		return new OAuth2ClientAuthenticationToken(registeredClient,
				clientAuthentication.getClientAuthenticationMethod(), null);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private static void throwInvalidClient(String parameterName) {
		OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
				"Client authentication failed: " + parameterName, ERROR_URI);
		throw new OAuth2AuthenticationException(error);
	}

}
