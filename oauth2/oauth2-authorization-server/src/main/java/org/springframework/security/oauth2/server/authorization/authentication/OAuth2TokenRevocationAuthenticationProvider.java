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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation for OAuth 2.0 Token Revocation.
 *
 * @author Vivek Babu
 * @author Joe Grandja
 * @since 7.0
 * @see OAuth2TokenRevocationAuthenticationToken
 * @see OAuth2AuthorizationService
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7009#section-2.1">Section
 * 2.1 Revocation Request</a>
 */
public final class OAuth2TokenRevocationAuthenticationProvider implements AuthenticationProvider {

	private final Log logger = LogFactory.getLog(getClass());

	private final OAuth2AuthorizationService authorizationService;

	/**
	 * Constructs an {@code OAuth2TokenRevocationAuthenticationProvider} using the
	 * provided parameters.
	 * @param authorizationService the authorization service
	 */
	public OAuth2TokenRevocationAuthenticationProvider(OAuth2AuthorizationService authorizationService) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.authorizationService = authorizationService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2TokenRevocationAuthenticationToken tokenRevocationAuthentication = (OAuth2TokenRevocationAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal = OAuth2AuthenticationProviderUtils
			.getAuthenticatedClientElseThrowInvalidClient(tokenRevocationAuthentication);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

		OAuth2Authorization authorization = this.authorizationService
			.findByToken(tokenRevocationAuthentication.getToken(), null);
		if (authorization == null) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Did not authenticate token revocation request since token was not found");
			}
			// Return the authentication request when token not found
			return tokenRevocationAuthentication;
		}

		if (!registeredClient.getId().equals(authorization.getRegisteredClientId())) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
		}

		OAuth2Authorization.Token<OAuth2Token> token = authorization.getToken(tokenRevocationAuthentication.getToken());
		authorization = OAuth2Authorization.from(authorization).invalidate(token.getToken()).build();
		this.authorizationService.save(authorization);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Saved authorization with revoked token");
			// This log is kept separate for consistency with other providers
			this.logger.trace("Authenticated token revocation request");
		}

		return new OAuth2TokenRevocationAuthenticationToken(token.getToken(), clientPrincipal);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2TokenRevocationAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
