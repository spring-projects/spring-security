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

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.Consumer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Client Credentials
 * Grant.
 *
 * @author Alexey Nesterov
 * @author Joe Grandja
 * @since 7.0
 * @see OAuth2ClientCredentialsAuthenticationToken
 * @see OAuth2AccessTokenAuthenticationToken
 * @see OAuth2AuthorizationService
 * @see OAuth2TokenGenerator
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc6749#section-4.4">Section 4.4 Client
 * Credentials Grant</a>
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.2">Section 4.4.2 Access
 * Token Request</a>
 */
public final class OAuth2ClientCredentialsAuthenticationProvider implements AuthenticationProvider {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

	private final Log logger = LogFactory.getLog(getClass());

	private final OAuth2AuthorizationService authorizationService;

	private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

	private Consumer<OAuth2ClientCredentialsAuthenticationContext> authenticationValidator = new OAuth2ClientCredentialsAuthenticationValidator();

	/**
	 * Constructs an {@code OAuth2ClientCredentialsAuthenticationProvider} using the
	 * provided parameters.
	 * @param authorizationService the authorization service
	 * @param tokenGenerator the token generator
	 */
	public OAuth2ClientCredentialsAuthenticationProvider(OAuth2AuthorizationService authorizationService,
			OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
		this.authorizationService = authorizationService;
		this.tokenGenerator = tokenGenerator;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2ClientCredentialsAuthenticationToken clientCredentialsAuthentication = (OAuth2ClientCredentialsAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal = OAuth2AuthenticationProviderUtils
			.getAuthenticatedClientElseThrowInvalidClient(clientCredentialsAuthentication);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved registered client");
		}

		if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.CLIENT_CREDENTIALS)) {
			if (this.logger.isDebugEnabled()) {
				this.logger.debug(LogMessage.format(
						"Invalid request: requested grant_type is not allowed" + " for registered client '%s'",
						registeredClient.getId()));
			}
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
		}

		OAuth2ClientCredentialsAuthenticationContext authenticationContext = OAuth2ClientCredentialsAuthenticationContext
			.with(clientCredentialsAuthentication)
			.registeredClient(registeredClient)
			.build();
		this.authenticationValidator.accept(authenticationContext);

		Set<String> authorizedScopes = new LinkedHashSet<>(clientCredentialsAuthentication.getScopes());

		// Verify the DPoP Proof (if available)
		Jwt dPoPProof = DPoPProofVerifier.verifyIfAvailable(clientCredentialsAuthentication);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Validated token request parameters");
		}

		// @formatter:off
		DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal(clientPrincipal)
				.authorizationServerContext(AuthorizationServerContextHolder.getContext())
				.authorizedScopes(authorizedScopes)
				.tokenType(OAuth2TokenType.ACCESS_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.authorizationGrant(clientCredentialsAuthentication);
		// @formatter:on
		if (dPoPProof != null) {
			tokenContextBuilder.put(OAuth2TokenContext.DPOP_PROOF_KEY, dPoPProof);
		}
		OAuth2TokenContext tokenContext = tokenContextBuilder.build();

		OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
		if (generatedAccessToken == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
					"The token generator failed to generate the access token.", ERROR_URI);
			throw new OAuth2AuthenticationException(error);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Generated access token");
		}

		// @formatter:off
		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(clientPrincipal.getName())
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.authorizedScopes(authorizedScopes);
		// @formatter:on

		OAuth2AccessToken accessToken = OAuth2AuthenticationProviderUtils.accessToken(authorizationBuilder,
				generatedAccessToken, tokenContext);

		OAuth2Authorization authorization = authorizationBuilder.build();

		this.authorizationService.save(authorization);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Saved authorization");
			// This log is kept separate for consistency with other providers
			this.logger.trace("Authenticated token request");
		}

		return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2ClientCredentialsAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * Sets the {@code Consumer} providing access to the
	 * {@link OAuth2ClientCredentialsAuthenticationContext} and is responsible for
	 * validating specific OAuth 2.0 Client Credentials Grant Request parameters
	 * associated in the {@link OAuth2ClientCredentialsAuthenticationToken}. The default
	 * authentication validator is {@link OAuth2ClientCredentialsAuthenticationValidator}.
	 *
	 * <p>
	 * <b>NOTE:</b> The authentication validator MUST throw
	 * {@link OAuth2AuthenticationException} if validation fails.
	 * @param authenticationValidator the {@code Consumer} providing access to the
	 * {@link OAuth2ClientCredentialsAuthenticationContext} and is responsible for
	 * validating specific OAuth 2.0 Client Credentials Grant Request parameters
	 */
	public void setAuthenticationValidator(
			Consumer<OAuth2ClientCredentialsAuthenticationContext> authenticationValidator) {
		Assert.notNull(authenticationValidator, "authenticationValidator cannot be null");
		this.authenticationValidator = authenticationValidator;
	}

}
