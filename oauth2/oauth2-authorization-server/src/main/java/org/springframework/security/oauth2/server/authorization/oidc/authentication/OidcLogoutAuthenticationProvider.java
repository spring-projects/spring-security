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

package org.springframework.security.oauth2.server.authorization.oidc.authentication;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.Base64;
import java.util.List;
import java.util.function.Consumer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * An {@link AuthenticationProvider} implementation for OpenID Connect 1.0 RP-Initiated
 * Logout Endpoint.
 *
 * @author Joe Grandja
 * @since 1.1
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see SessionRegistry
 * @see <a href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout">2.
 * RP-Initiated Logout</a>
 */
public final class OidcLogoutAuthenticationProvider implements AuthenticationProvider {

	private static final OAuth2TokenType ID_TOKEN_TOKEN_TYPE = new OAuth2TokenType(OidcParameterNames.ID_TOKEN);

	private final Log logger = LogFactory.getLog(getClass());

	private final RegisteredClientRepository registeredClientRepository;

	private final OAuth2AuthorizationService authorizationService;

	private final SessionRegistry sessionRegistry;

	private Consumer<OidcLogoutAuthenticationContext> authenticationValidator = new OidcLogoutAuthenticationValidator();

	/**
	 * Constructs an {@code OidcLogoutAuthenticationProvider} using the provided
	 * parameters.
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 * @param sessionRegistry the {@link SessionRegistry} used to track OpenID Connect
	 * sessions
	 */
	public OidcLogoutAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService, SessionRegistry sessionRegistry) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(sessionRegistry, "sessionRegistry cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationService = authorizationService;
		this.sessionRegistry = sessionRegistry;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OidcLogoutAuthenticationToken oidcLogoutAuthentication = (OidcLogoutAuthenticationToken) authentication;

		OAuth2Authorization authorization = this.authorizationService
			.findByToken(oidcLogoutAuthentication.getIdTokenHint(), ID_TOKEN_TOKEN_TYPE);
		if (authorization == null) {
			throwError(OAuth2ErrorCodes.INVALID_TOKEN, "id_token_hint");
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved authorization with ID Token");
		}

		OAuth2Authorization.Token<OidcIdToken> authorizedIdToken = authorization.getToken(OidcIdToken.class);
		if (authorizedIdToken.isInvalidated() || authorizedIdToken.isBeforeUse()) {
			// Expired ID Token should be accepted
			throwError(OAuth2ErrorCodes.INVALID_TOKEN, "id_token_hint");
		}

		RegisteredClient registeredClient = this.registeredClientRepository
			.findById(authorization.getRegisteredClientId());

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved registered client");
		}

		OidcIdToken idToken = authorizedIdToken.getToken();

		// Validate client identity
		List<String> audClaim = idToken.getAudience();
		if (CollectionUtils.isEmpty(audClaim) || !audClaim.contains(registeredClient.getClientId())) {
			throwError(OAuth2ErrorCodes.INVALID_TOKEN, IdTokenClaimNames.AUD);
		}
		if (StringUtils.hasText(oidcLogoutAuthentication.getClientId())
				&& !oidcLogoutAuthentication.getClientId().equals(registeredClient.getClientId())) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID);
		}

		OidcLogoutAuthenticationContext context = OidcLogoutAuthenticationContext.with(oidcLogoutAuthentication)
			.registeredClient(registeredClient)
			.build();
		this.authenticationValidator.accept(context);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Validated logout request parameters");
		}

		// Validate user identity
		if (oidcLogoutAuthentication.isPrincipalAuthenticated()) {
			Authentication currentUserPrincipal = (Authentication) oidcLogoutAuthentication.getPrincipal();
			Authentication authorizedUserPrincipal = authorization.getAttribute(Principal.class.getName());
			if (!StringUtils.hasText(idToken.getSubject())
					|| !currentUserPrincipal.getName().equals(authorizedUserPrincipal.getName())) {
				throwError(OAuth2ErrorCodes.INVALID_TOKEN, IdTokenClaimNames.SUB);
			}

			// Check for active session
			if (StringUtils.hasText(oidcLogoutAuthentication.getSessionId())) {
				SessionInformation sessionInformation = findSessionInformation(currentUserPrincipal,
						oidcLogoutAuthentication.getSessionId());
				if (sessionInformation != null) {
					String sessionIdHash;
					try {
						sessionIdHash = createHash(sessionInformation.getSessionId());
					}
					catch (NoSuchAlgorithmException ex) {
						OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
								"Failed to compute hash for Session ID.", null);
						throw new OAuth2AuthenticationException(error);
					}

					String sidClaim = idToken.getClaim("sid");
					if (!StringUtils.hasText(sidClaim) || !sidClaim.equals(sessionIdHash)) {
						throwError(OAuth2ErrorCodes.INVALID_TOKEN, "sid");
					}
				}
			}
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Authenticated logout request");
		}

		return new OidcLogoutAuthenticationToken(idToken, (Authentication) oidcLogoutAuthentication.getPrincipal(),
				oidcLogoutAuthentication.getSessionId(), oidcLogoutAuthentication.getClientId(),
				oidcLogoutAuthentication.getPostLogoutRedirectUri(), oidcLogoutAuthentication.getState());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OidcLogoutAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * Sets the {@code Consumer} providing access to the
	 * {@link OidcLogoutAuthenticationContext} and is responsible for validating specific
	 * OpenID Connect RP-Initiated Logout Request parameters associated in the
	 * {@link OidcLogoutAuthenticationToken}. The default authentication validator is
	 * {@link OidcLogoutAuthenticationValidator}.
	 *
	 * <p>
	 * <b>NOTE:</b> The authentication validator MUST throw
	 * {@link OAuth2AuthenticationException} if validation fails.
	 * @param authenticationValidator the {@code Consumer} providing access to the
	 * {@link OidcLogoutAuthenticationContext} and is responsible for validating specific
	 * OpenID Connect RP-Initiated Logout Request parameters
	 * @since 1.4
	 */
	public void setAuthenticationValidator(Consumer<OidcLogoutAuthenticationContext> authenticationValidator) {
		Assert.notNull(authenticationValidator, "authenticationValidator cannot be null");
		this.authenticationValidator = authenticationValidator;
	}

	private SessionInformation findSessionInformation(Authentication principal, String sessionId) {
		List<SessionInformation> sessions = this.sessionRegistry.getAllSessions(principal.getPrincipal(), true);
		SessionInformation sessionInformation = null;
		if (!CollectionUtils.isEmpty(sessions)) {
			for (SessionInformation session : sessions) {
				if (session.getSessionId().equals(sessionId)) {
					sessionInformation = session;
					break;
				}
			}
		}
		return sessionInformation;
	}

	private static void throwError(String errorCode, String parameterName) {
		OAuth2Error error = new OAuth2Error(errorCode, "OpenID Connect 1.0 Logout Request Parameter: " + parameterName,
				"https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ValidationAndErrorHandling");
		throw new OAuth2AuthenticationException(error);
	}

	private static String createHash(String value) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(value.getBytes(StandardCharsets.US_ASCII));
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
	}

}
