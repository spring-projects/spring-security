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
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation used for OAuth 2.0 Client
 * Authentication, which authenticates the {@link Jwt}
 * {@link OAuth2ParameterNames#CLIENT_ASSERTION client_assertion} parameter.
 *
 * @author Rafal Lewczuk
 * @author Joe Grandja
 * @since 0.2.3
 * @see AuthenticationProvider
 * @see OAuth2ClientAuthenticationToken
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see JwtClientAssertionDecoderFactory
 */
public final class JwtClientAssertionAuthenticationProvider implements AuthenticationProvider {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1";

	private static final ClientAuthenticationMethod JWT_CLIENT_ASSERTION_AUTHENTICATION_METHOD = new ClientAuthenticationMethod(
			"urn:ietf:params:oauth:client-assertion-type:jwt-bearer");

	private final Log logger = LogFactory.getLog(getClass());

	private final RegisteredClientRepository registeredClientRepository;

	private final CodeVerifierAuthenticator codeVerifierAuthenticator;

	private JwtDecoderFactory<RegisteredClient> jwtDecoderFactory;

	/**
	 * Constructs a {@code JwtClientAssertionAuthenticationProvider} using the provided
	 * parameters.
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 */
	public JwtClientAssertionAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.codeVerifierAuthenticator = new CodeVerifierAuthenticator(authorizationService);
		this.jwtDecoderFactory = new JwtClientAssertionDecoderFactory();
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2ClientAuthenticationToken clientAuthentication = (OAuth2ClientAuthenticationToken) authentication;

		if (!JWT_CLIENT_ASSERTION_AUTHENTICATION_METHOD.equals(clientAuthentication.getClientAuthenticationMethod())) {
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

		// @formatter:off
		if (!registeredClient.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.PRIVATE_KEY_JWT) &&
				!registeredClient.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.CLIENT_SECRET_JWT)) {
			throwInvalidClient("authentication_method");
		}
		// @formatter:on

		if (clientAuthentication.getCredentials() == null) {
			throwInvalidClient("credentials");
		}

		Jwt jwtAssertion = null;
		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(registeredClient);
		try {
			jwtAssertion = jwtDecoder.decode(clientAuthentication.getCredentials().toString());
		}
		catch (JwtException ex) {
			throwInvalidClient(OAuth2ParameterNames.CLIENT_ASSERTION, ex);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Validated client authentication parameters");
		}

		// Validate the "code_verifier" parameter for the confidential client, if
		// available
		this.codeVerifierAuthenticator.authenticateIfAvailable(clientAuthentication, registeredClient);

		// @formatter:off
		ClientAuthenticationMethod clientAuthenticationMethod =
				(registeredClient.getClientSettings().getTokenEndpointAuthenticationSigningAlgorithm() instanceof SignatureAlgorithm) ?
						ClientAuthenticationMethod.PRIVATE_KEY_JWT :
						ClientAuthenticationMethod.CLIENT_SECRET_JWT;
		// @formatter:on

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Authenticated client assertion");
		}

		return new OAuth2ClientAuthenticationToken(registeredClient, clientAuthenticationMethod, jwtAssertion);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * Sets the {@link JwtDecoderFactory} that provides a {@link JwtDecoder} for the
	 * specified {@link RegisteredClient} and is used for authenticating a {@link Jwt}
	 * Bearer Token during OAuth 2.0 Client Authentication. The default factory is
	 * {@link JwtClientAssertionDecoderFactory}.
	 * @param jwtDecoderFactory the {@link JwtDecoderFactory} that provides a
	 * {@link JwtDecoder} for the specified {@link RegisteredClient}
	 * @since 0.4.0
	 */
	public void setJwtDecoderFactory(JwtDecoderFactory<RegisteredClient> jwtDecoderFactory) {
		Assert.notNull(jwtDecoderFactory, "jwtDecoderFactory cannot be null");
		this.jwtDecoderFactory = jwtDecoderFactory;
	}

	private static void throwInvalidClient(String parameterName) {
		throwInvalidClient(parameterName, null);
	}

	private static void throwInvalidClient(String parameterName, Throwable cause) {
		OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
				"Client authentication failed: " + parameterName, ERROR_URI);
		throw new OAuth2AuthenticationException(error, error.toString(), cause);
	}

}
