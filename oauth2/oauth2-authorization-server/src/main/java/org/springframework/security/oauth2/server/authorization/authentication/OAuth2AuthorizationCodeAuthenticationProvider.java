/*
 * Copyright 2020-2025 the original author or authors.
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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Authorization Code
 * Grant.
 *
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 * @since 0.0.1
 * @see OAuth2AuthorizationCodeAuthenticationToken
 * @see OAuth2AccessTokenAuthenticationToken
 * @see OAuth2AuthorizationCodeRequestAuthenticationProvider
 * @see OAuth2AuthorizationService
 * @see OAuth2TokenGenerator
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1">Section 4.1 Authorization
 * Code Grant</a>
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3">Section 4.1.3 Access
 * Token Request</a>
 */
public final class OAuth2AuthorizationCodeAuthenticationProvider implements AuthenticationProvider {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

	private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.CODE);

	private static final OAuth2TokenType ID_TOKEN_TOKEN_TYPE = new OAuth2TokenType(OidcParameterNames.ID_TOKEN);

	private final Log logger = LogFactory.getLog(getClass());

	private final OAuth2AuthorizationService authorizationService;

	private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

	private SessionRegistry sessionRegistry;

	/**
	 * Constructs an {@code OAuth2AuthorizationCodeAuthenticationProvider} using the
	 * provided parameters.
	 * @param authorizationService the authorization service
	 * @param tokenGenerator the token generator
	 * @since 0.2.3
	 */
	public OAuth2AuthorizationCodeAuthenticationProvider(OAuth2AuthorizationService authorizationService,
			OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
		this.authorizationService = authorizationService;
		this.tokenGenerator = tokenGenerator;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication = (OAuth2AuthorizationCodeAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal = OAuth2AuthenticationProviderUtils
			.getAuthenticatedClientElseThrowInvalidClient(authorizationCodeAuthentication);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved registered client");
		}

		OAuth2Authorization authorization = this.authorizationService
			.findByToken(authorizationCodeAuthentication.getCode(), AUTHORIZATION_CODE_TOKEN_TYPE);
		if (authorization == null) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved authorization with authorization code");
		}

		OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = authorization
			.getToken(OAuth2AuthorizationCode.class);

		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());

		if (!registeredClient.getClientId().equals(authorizationRequest.getClientId())) {
			if (!authorizationCode.isInvalidated()) {
				// Invalidate the authorization code given that a different client is
				// attempting to use it
				authorization = OAuth2Authorization.from(authorization)
					.invalidate(authorizationCode.getToken())
					.build();
				this.authorizationService.save(authorization);
				if (this.logger.isWarnEnabled()) {
					this.logger.warn(LogMessage.format("Invalidated authorization code used by registered client '%s'",
							registeredClient.getId()));
				}
			}
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		if (StringUtils.hasText(authorizationRequest.getRedirectUri())
				&& !authorizationRequest.getRedirectUri().equals(authorizationCodeAuthentication.getRedirectUri())) {
			if (this.logger.isDebugEnabled()) {
				this.logger.debug(LogMessage.format(
						"Invalid request: redirect_uri does not match" + " for registered client '%s'",
						registeredClient.getId()));
			}
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		if (!authorizationCode.isActive()) {
			if (authorizationCode.isInvalidated()) {
				OAuth2Authorization.Token<? extends OAuth2Token> token = (authorization.getRefreshToken() != null)
						? authorization.getRefreshToken() : authorization.getAccessToken();
				if (token != null) {
					// Invalidate the access (and refresh) token as the client is
					// attempting to use the authorization code more than once
					authorization = OAuth2Authorization.from(authorization).invalidate(token.getToken()).build();
					this.authorizationService.save(authorization);
					if (this.logger.isWarnEnabled()) {
						this.logger.warn(LogMessage.format(
								"Invalidated authorization token(s) previously issued to registered client '%s'",
								registeredClient.getId()));
					}
				}
			}
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		// Verify the DPoP Proof (if available)
		Jwt dPoPProof = DPoPProofVerifier.verifyIfAvailable(authorizationCodeAuthentication);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Validated token request parameters");
		}

		Authentication principal = authorization.getAttribute(Principal.class.getName());

		// @formatter:off
		DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal(principal)
				.authorizationServerContext(AuthorizationServerContextHolder.getContext())
				.authorization(authorization)
				.authorizedScopes(authorization.getAuthorizedScopes())
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrant(authorizationCodeAuthentication);
		// @formatter:on
		if (dPoPProof != null) {
			tokenContextBuilder.put(OAuth2TokenContext.DPOP_PROOF_KEY, dPoPProof);
		}

		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization);

		// ----- Access token -----
		OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
		OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
		if (generatedAccessToken == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
					"The token generator failed to generate the access token.", ERROR_URI);
			throw new OAuth2AuthenticationException(error);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Generated access token");
		}

		OAuth2AccessToken accessToken = OAuth2AuthenticationProviderUtils.accessToken(authorizationBuilder,
				generatedAccessToken, tokenContext);

		// ----- Refresh token -----
		OAuth2RefreshToken refreshToken = null;
		// Do not issue refresh token to public client
		if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
			tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
			OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
			if (generatedRefreshToken != null) {
				if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
					OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
							"The token generator failed to generate a valid refresh token.", ERROR_URI);
					throw new OAuth2AuthenticationException(error);
				}

				if (this.logger.isTraceEnabled()) {
					this.logger.trace("Generated refresh token");
				}

				refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
				authorizationBuilder.refreshToken(refreshToken);
			}
		}

		// ----- ID token -----
		OidcIdToken idToken;
		if (authorizationRequest.getScopes().contains(OidcScopes.OPENID)) {
			SessionInformation sessionInformation = getSessionInformation(principal);
			if (sessionInformation != null) {
				try {
					// Compute (and use) hash for Session ID
					sessionInformation = new SessionInformation(sessionInformation.getPrincipal(),
							createHash(sessionInformation.getSessionId()), sessionInformation.getLastRequest());
				}
				catch (NoSuchAlgorithmException ex) {
					OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
							"Failed to compute hash for Session ID.", ERROR_URI);
					throw new OAuth2AuthenticationException(error);
				}
				tokenContextBuilder.put(SessionInformation.class, sessionInformation);
			}
			// @formatter:off
			tokenContext = tokenContextBuilder
					.tokenType(ID_TOKEN_TOKEN_TYPE)
					.authorization(authorizationBuilder.build())	// ID token customizer may need access to the access token and/or refresh token
					.build();
			// @formatter:on
			OAuth2Token generatedIdToken = this.tokenGenerator.generate(tokenContext);
			if (!(generatedIdToken instanceof Jwt)) {
				OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
						"The token generator failed to generate the ID token.", ERROR_URI);
				throw new OAuth2AuthenticationException(error);
			}

			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Generated id token");
			}

			idToken = new OidcIdToken(generatedIdToken.getTokenValue(), generatedIdToken.getIssuedAt(),
					generatedIdToken.getExpiresAt(), ((Jwt) generatedIdToken).getClaims());
			authorizationBuilder.token(idToken,
					(metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims()));
		}
		else {
			idToken = null;
		}

		// Invalidate the authorization code as it can only be used once
		authorizationBuilder.invalidate(authorizationCode.getToken());

		authorization = authorizationBuilder.build();

		this.authorizationService.save(authorization);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Saved authorization");
		}

		Map<String, Object> additionalParameters = Collections.emptyMap();
		if (idToken != null) {
			additionalParameters = new HashMap<>();
			additionalParameters.put(OidcParameterNames.ID_TOKEN, idToken.getTokenValue());
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Authenticated token request");
		}

		return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, refreshToken,
				additionalParameters);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * Sets the {@link SessionRegistry} used to track OpenID Connect sessions.
	 * @param sessionRegistry the {@link SessionRegistry} used to track OpenID Connect
	 * sessions
	 * @since 1.1
	 */
	public void setSessionRegistry(SessionRegistry sessionRegistry) {
		Assert.notNull(sessionRegistry, "sessionRegistry cannot be null");
		this.sessionRegistry = sessionRegistry;
	}

	private SessionInformation getSessionInformation(Authentication principal) {
		SessionInformation sessionInformation = null;
		if (this.sessionRegistry != null) {
			List<SessionInformation> sessions = this.sessionRegistry.getAllSessions(principal.getPrincipal(), false);
			if (!CollectionUtils.isEmpty(sessions)) {
				sessionInformation = sessions.get(0);
				if (sessions.size() > 1) {
					// Get the most recent session
					sessions = new ArrayList<>(sessions);
					sessions.sort(Comparator.comparing(SessionInformation::getLastRequest));
					sessionInformation = sessions.get(sessions.size() - 1);
				}
			}
		}
		return sessionInformation;
	}

	private static String createHash(String value) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(value.getBytes(StandardCharsets.US_ASCII));
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
	}

}
