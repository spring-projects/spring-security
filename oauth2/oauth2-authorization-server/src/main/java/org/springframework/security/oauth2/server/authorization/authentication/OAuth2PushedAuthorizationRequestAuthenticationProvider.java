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

import java.util.function.Consumer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Pushed Authorization
 * Request used in the Authorization Code Grant.
 *
 * @author Joe Grandja
 * @since 1.5
 * @see OAuth2PushedAuthorizationRequestAuthenticationToken
 * @see OAuth2AuthorizationCodeRequestAuthenticationToken
 * @see OAuth2AuthorizationCodeRequestAuthenticationValidator
 * @see OAuth2AuthorizationService
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc9126#section-2.1">Section 2.1 Pushed
 * Authorization Request</a>
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc9126#section-2.2">Section 2.2 Pushed
 * Authorization Response</a>
 */
public final class OAuth2PushedAuthorizationRequestAuthenticationProvider implements AuthenticationProvider {

	private final Log logger = LogFactory.getLog(getClass());

	private final OAuth2AuthorizationService authorizationService;

	private Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator = new OAuth2AuthorizationCodeRequestAuthenticationValidator();

	/**
	 * Constructs an {@code OAuth2PushedAuthorizationRequestAuthenticationProvider} using
	 * the provided parameters.
	 * @param authorizationService the authorization service
	 */
	public OAuth2PushedAuthorizationRequestAuthenticationProvider(OAuth2AuthorizationService authorizationService) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.authorizationService = authorizationService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2PushedAuthorizationRequestAuthenticationToken pushedAuthorizationRequestAuthentication = (OAuth2PushedAuthorizationRequestAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal = OAuth2AuthenticationProviderUtils
			.getAuthenticatedClientElseThrowInvalidClient(pushedAuthorizationRequestAuthentication);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved registered client");
		}

		OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext = OAuth2AuthorizationCodeRequestAuthenticationContext
			.with(toAuthorizationCodeRequestAuthentication(pushedAuthorizationRequestAuthentication))
			.registeredClient(registeredClient)
			.build();

		// grant_type
		OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_AUTHORIZATION_GRANT_TYPE_VALIDATOR
			.accept(authenticationContext);

		// redirect_uri and scope
		this.authenticationValidator.accept(authenticationContext);

		// code_challenge (REQUIRED for public clients) - RFC 7636 (PKCE)
		OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_CODE_CHALLENGE_VALIDATOR
			.accept(authenticationContext);

		// prompt (OPTIONAL for OpenID Connect 1.0 Authentication Request)
		OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_PROMPT_VALIDATOR.accept(authenticationContext);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Validated pushed authorization request parameters");
		}

		// @formatter:off
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
			.authorizationUri(pushedAuthorizationRequestAuthentication.getAuthorizationUri())
			.clientId(registeredClient.getClientId())
			.redirectUri(pushedAuthorizationRequestAuthentication.getRedirectUri())
			.scopes(pushedAuthorizationRequestAuthentication.getScopes())
			.state(pushedAuthorizationRequestAuthentication.getState())
			.additionalParameters(pushedAuthorizationRequestAuthentication.getAdditionalParameters())
			.build();
		// @formatter:on

		OAuth2PushedAuthorizationRequestUri pushedAuthorizationRequestUri = OAuth2PushedAuthorizationRequestUri
			.create();

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Generated pushed authorization request uri");
		}

		// @formatter:off
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(clientPrincipal.getName())
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest)
				.attribute(OAuth2ParameterNames.STATE, pushedAuthorizationRequestUri.getState())
				.build();
		// @formatter:on
		this.authorizationService.save(authorization);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Saved authorization");
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Authenticated pushed authorization request");
		}

		return new OAuth2PushedAuthorizationRequestAuthenticationToken(authorizationRequest.getAuthorizationUri(),
				authorizationRequest.getClientId(), clientPrincipal, pushedAuthorizationRequestUri.getRequestUri(),
				pushedAuthorizationRequestUri.getExpiresAt(), authorizationRequest.getRedirectUri(),
				authorizationRequest.getState(), authorizationRequest.getScopes());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2PushedAuthorizationRequestAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * Sets the {@code Consumer} providing access to the
	 * {@link OAuth2AuthorizationCodeRequestAuthenticationContext} and is responsible for
	 * validating specific OAuth 2.0 Pushed Authorization Request parameters associated in
	 * the {@link OAuth2AuthorizationCodeRequestAuthenticationToken}. The default
	 * authentication validator is
	 * {@link OAuth2AuthorizationCodeRequestAuthenticationValidator}.
	 *
	 * <p>
	 * <b>NOTE:</b> The authentication validator MUST throw
	 * {@link OAuth2AuthorizationCodeRequestAuthenticationException} if validation fails.
	 * @param authenticationValidator the {@code Consumer} providing access to the
	 * {@link OAuth2AuthorizationCodeRequestAuthenticationContext} and is responsible for
	 * validating specific OAuth 2.0 Pushed Authorization Request parameters
	 */
	public void setAuthenticationValidator(
			Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator) {
		Assert.notNull(authenticationValidator, "authenticationValidator cannot be null");
		this.authenticationValidator = authenticationValidator;
	}

	private static OAuth2AuthorizationCodeRequestAuthenticationToken toAuthorizationCodeRequestAuthentication(
			OAuth2PushedAuthorizationRequestAuthenticationToken pushedAuthorizationCodeRequestAuthentication) {
		return new OAuth2AuthorizationCodeRequestAuthenticationToken(
				pushedAuthorizationCodeRequestAuthentication.getAuthorizationUri(),
				pushedAuthorizationCodeRequestAuthentication.getClientId(),
				(Authentication) pushedAuthorizationCodeRequestAuthentication.getPrincipal(),
				pushedAuthorizationCodeRequestAuthentication.getRedirectUri(),
				pushedAuthorizationCodeRequestAuthentication.getState(),
				pushedAuthorizationCodeRequestAuthentication.getScopes(),
				pushedAuthorizationCodeRequestAuthentication.getAdditionalParameters());
	}

}
