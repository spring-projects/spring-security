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

import java.security.Principal;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Predicate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Authorization
 * Request used in the Authorization Code Grant.
 *
 * @author Joe Grandja
 * @author Steve Riesenberg
 * @since 7.0
 * @see OAuth2AuthorizationCodeRequestAuthenticationToken
 * @see OAuth2AuthorizationCodeRequestAuthenticationValidator
 * @see OAuth2AuthorizationCodeAuthenticationProvider
 * @see OAuth2AuthorizationConsentAuthenticationProvider
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see OAuth2AuthorizationConsentService
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1">Section 4.1.1
 * Authorization Request</a>
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">Section 3.1.2.1
 * Authentication Request</a>
 */
public final class OAuth2AuthorizationCodeRequestAuthenticationProvider implements AuthenticationProvider {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";

	private static final OAuth2TokenType STATE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.STATE);

	private static final StringKeyGenerator DEFAULT_STATE_GENERATOR = new Base64StringKeyGenerator(
			Base64.getUrlEncoder());

	private final Log logger = LogFactory.getLog(getClass());

	private final RegisteredClientRepository registeredClientRepository;

	private final OAuth2AuthorizationService authorizationService;

	private final OAuth2AuthorizationConsentService authorizationConsentService;

	private OAuth2TokenGenerator<OAuth2AuthorizationCode> authorizationCodeGenerator = new OAuth2AuthorizationCodeGenerator();

	private Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator = new OAuth2AuthorizationCodeRequestAuthenticationValidator();

	private Predicate<OAuth2AuthorizationCodeRequestAuthenticationContext> authorizationConsentRequired = OAuth2AuthorizationCodeRequestAuthenticationProvider::isAuthorizationConsentRequired;

	/**
	 * Constructs an {@code OAuth2AuthorizationCodeRequestAuthenticationProvider} using
	 * the provided parameters.
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 * @param authorizationConsentService the authorization consent service
	 */
	public OAuth2AuthorizationCodeRequestAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService,
			OAuth2AuthorizationConsentService authorizationConsentService) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(authorizationConsentService, "authorizationConsentService cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationService = authorizationService;
		this.authorizationConsentService = authorizationConsentService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;

		OAuth2Authorization pushedAuthorization = null;
		String requestUri = (String) authorizationCodeRequestAuthentication.getAdditionalParameters()
			.get(OAuth2ParameterNames.REQUEST_URI);
		if (StringUtils.hasText(requestUri)) {
			OAuth2PushedAuthorizationRequestUri pushedAuthorizationRequestUri = null;
			try {
				pushedAuthorizationRequestUri = OAuth2PushedAuthorizationRequestUri.parse(requestUri);
			}
			catch (Exception ex) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REQUEST_URI,
						authorizationCodeRequestAuthentication, null);
			}

			pushedAuthorization = this.authorizationService.findByToken(pushedAuthorizationRequestUri.getState(),
					STATE_TOKEN_TYPE);
			if (pushedAuthorization == null) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REQUEST_URI,
						authorizationCodeRequestAuthentication, null);
			}

			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Retrieved authorization with pushed authorization request");
			}

			OAuth2AuthorizationRequest authorizationRequest = pushedAuthorization
				.getAttribute(OAuth2AuthorizationRequest.class.getName());

			if (!authorizationCodeRequestAuthentication.getClientId().equals(authorizationRequest.getClientId())) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID,
						authorizationCodeRequestAuthentication, null);
			}

			if (Instant.now().isAfter(pushedAuthorizationRequestUri.getExpiresAt())) {
				// Remove (effectively invalidating) the pushed authorization request
				this.authorizationService.remove(pushedAuthorization);
				if (this.logger.isWarnEnabled()) {
					this.logger
						.warn(LogMessage.format("Removed expired pushed authorization request for client id '%s'",
								authorizationRequest.getClientId()));
				}
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REQUEST_URI,
						authorizationCodeRequestAuthentication, null);
			}

			authorizationCodeRequestAuthentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
					authorizationCodeRequestAuthentication.getAuthorizationUri(), authorizationRequest.getClientId(),
					(Authentication) authorizationCodeRequestAuthentication.getPrincipal(),
					authorizationRequest.getRedirectUri(), authorizationRequest.getState(),
					authorizationRequest.getScopes(), authorizationRequest.getAdditionalParameters());
		}

		RegisteredClient registeredClient = this.registeredClientRepository
			.findByClientId(authorizationCodeRequestAuthentication.getClientId());
		if (registeredClient == null) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID,
					authorizationCodeRequestAuthentication, null);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved registered client");
		}

		OAuth2AuthorizationCodeRequestAuthenticationContext.Builder authenticationContextBuilder = OAuth2AuthorizationCodeRequestAuthenticationContext
			.with(authorizationCodeRequestAuthentication)
			.registeredClient(registeredClient);
		OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext = authenticationContextBuilder
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
		Set<String> promptValues = Collections.emptySet();
		if (authorizationCodeRequestAuthentication.getScopes().contains(OidcScopes.OPENID)) {
			String prompt = (String) authorizationCodeRequestAuthentication.getAdditionalParameters().get("prompt");
			if (StringUtils.hasText(prompt)) {
				OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_PROMPT_VALIDATOR
					.accept(authenticationContext);
				promptValues = new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(prompt, " ")));
			}
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Validated authorization code request parameters");
		}

		// ---------------
		// The request is valid - ensure the resource owner is authenticated
		// ---------------

		Authentication principal = (Authentication) authorizationCodeRequestAuthentication.getPrincipal();
		if (!isPrincipalAuthenticated(principal)) {
			if (promptValues.contains(OidcPrompt.NONE)) {
				// Return an error instead of displaying the login page (via the
				// configured AuthenticationEntryPoint)
				throwError("login_required", "prompt", authorizationCodeRequestAuthentication, registeredClient);
			}
			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Did not authenticate authorization code request since principal not authenticated");
			}
			// Return the authorization request as-is where isAuthenticated() is false
			return authorizationCodeRequestAuthentication;
		}

		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
			.authorizationUri(authorizationCodeRequestAuthentication.getAuthorizationUri())
			.clientId(registeredClient.getClientId())
			.redirectUri(authorizationCodeRequestAuthentication.getRedirectUri())
			.scopes(authorizationCodeRequestAuthentication.getScopes())
			.state(authorizationCodeRequestAuthentication.getState())
			.additionalParameters(authorizationCodeRequestAuthentication.getAdditionalParameters())
			.build();
		authenticationContextBuilder.authorizationRequest(authorizationRequest);

		OAuth2AuthorizationConsent currentAuthorizationConsent = this.authorizationConsentService
			.findById(registeredClient.getId(), principal.getName());
		if (currentAuthorizationConsent != null) {
			authenticationContextBuilder.authorizationConsent(currentAuthorizationConsent);
		}

		if (this.authorizationConsentRequired.test(authenticationContextBuilder.build())) {
			if (promptValues.contains(OidcPrompt.NONE)) {
				// Return an error instead of displaying the consent page
				throwError("consent_required", "prompt", authorizationCodeRequestAuthentication, registeredClient);
			}

			String state = DEFAULT_STATE_GENERATOR.generateKey();
			OAuth2Authorization authorization = authorizationBuilder(registeredClient, principal, authorizationRequest)
				.attribute(OAuth2ParameterNames.STATE, state)
				.build();

			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Generated authorization consent state");
			}

			this.authorizationService.save(authorization);

			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Saved authorization");
			}

			if (pushedAuthorization != null) {
				// Enforce one-time use by removing the pushed authorization request
				this.authorizationService.remove(pushedAuthorization);
				if (this.logger.isTraceEnabled()) {
					this.logger.trace("Removed authorization with pushed authorization request");
				}
			}

			Set<String> currentAuthorizedScopes = (currentAuthorizationConsent != null)
					? currentAuthorizationConsent.getScopes() : null;

			Map<String, Object> additionalParameters = new HashMap<>();
			if (pushedAuthorization != null) {
				additionalParameters.put(OAuth2ParameterNames.SCOPE, authorizationRequest.getScopes());
			}

			return new OAuth2AuthorizationConsentAuthenticationToken(authorizationRequest.getAuthorizationUri(),
					registeredClient.getClientId(), principal, state, currentAuthorizedScopes, additionalParameters);
		}

		OAuth2TokenContext tokenContext = createAuthorizationCodeTokenContext(authorizationCodeRequestAuthentication,
				registeredClient, null, authorizationRequest.getScopes());
		OAuth2AuthorizationCode authorizationCode = this.authorizationCodeGenerator.generate(tokenContext);
		if (authorizationCode == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
					"The token generator failed to generate the authorization code.", ERROR_URI);
			throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Generated authorization code");
		}

		OAuth2Authorization authorization = authorizationBuilder(registeredClient, principal, authorizationRequest)
			.authorizedScopes(authorizationRequest.getScopes())
			.token(authorizationCode)
			.build();
		this.authorizationService.save(authorization);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Saved authorization");
		}

		if (pushedAuthorization != null) {
			// Enforce one-time use by removing the pushed authorization request
			this.authorizationService.remove(pushedAuthorization);
			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Removed authorization with pushed authorization request");
			}
		}

		String redirectUri = authorizationRequest.getRedirectUri();
		if (!StringUtils.hasText(redirectUri)) {
			redirectUri = registeredClient.getRedirectUris().iterator().next();
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Authenticated authorization code request");
		}

		return new OAuth2AuthorizationCodeRequestAuthenticationToken(authorizationRequest.getAuthorizationUri(),
				registeredClient.getClientId(), principal, authorizationCode, redirectUri,
				authorizationRequest.getState(), authorizationRequest.getScopes());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2AuthorizationCodeRequestAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * Sets the {@link OAuth2TokenGenerator} that generates the
	 * {@link OAuth2AuthorizationCode}.
	 * @param authorizationCodeGenerator the {@link OAuth2TokenGenerator} that generates
	 * the {@link OAuth2AuthorizationCode}
	 */
	public void setAuthorizationCodeGenerator(
			OAuth2TokenGenerator<OAuth2AuthorizationCode> authorizationCodeGenerator) {
		Assert.notNull(authorizationCodeGenerator, "authorizationCodeGenerator cannot be null");
		this.authorizationCodeGenerator = authorizationCodeGenerator;
	}

	/**
	 * Sets the {@code Consumer} providing access to the
	 * {@link OAuth2AuthorizationCodeRequestAuthenticationContext} and is responsible for
	 * validating specific OAuth 2.0 Authorization Request parameters associated in the
	 * {@link OAuth2AuthorizationCodeRequestAuthenticationToken}. The default
	 * authentication validator is
	 * {@link OAuth2AuthorizationCodeRequestAuthenticationValidator}.
	 *
	 * <p>
	 * <b>NOTE:</b> The authentication validator MUST throw
	 * {@link OAuth2AuthorizationCodeRequestAuthenticationException} if validation fails.
	 * @param authenticationValidator the {@code Consumer} providing access to the
	 * {@link OAuth2AuthorizationCodeRequestAuthenticationContext} and is responsible for
	 * validating specific OAuth 2.0 Authorization Request parameters
	 */
	public void setAuthenticationValidator(
			Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator) {
		Assert.notNull(authenticationValidator, "authenticationValidator cannot be null");
		this.authenticationValidator = authenticationValidator;
	}

	/**
	 * Sets the {@code Predicate} used to determine if authorization consent is required.
	 *
	 * <p>
	 * The {@link OAuth2AuthorizationCodeRequestAuthenticationContext} gives the predicate
	 * access to the {@link OAuth2AuthorizationCodeRequestAuthenticationToken}, as well
	 * as, the following context attributes:
	 * <ul>
	 * <li>The {@link RegisteredClient} associated with the authorization request.</li>
	 * <li>The {@link OAuth2AuthorizationRequest} containing the authorization request
	 * parameters.</li>
	 * <li>The {@link OAuth2AuthorizationConsent} previously granted to the
	 * {@link RegisteredClient}, or {@code null} if not available.</li>
	 * </ul>
	 * @param authorizationConsentRequired the {@code Predicate} used to determine if
	 * authorization consent is required
	 */
	public void setAuthorizationConsentRequired(
			Predicate<OAuth2AuthorizationCodeRequestAuthenticationContext> authorizationConsentRequired) {
		Assert.notNull(authorizationConsentRequired, "authorizationConsentRequired cannot be null");
		this.authorizationConsentRequired = authorizationConsentRequired;
	}

	private static boolean isAuthorizationConsentRequired(
			OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext) {
		if (!authenticationContext.getRegisteredClient().getClientSettings().isRequireAuthorizationConsent()) {
			return false;
		}
		// 'openid' scope does not require consent
		if (authenticationContext.getAuthorizationRequest().getScopes().contains(OidcScopes.OPENID)
				&& authenticationContext.getAuthorizationRequest().getScopes().size() == 1) {
			return false;
		}

		if (authenticationContext.getAuthorizationConsent() != null && authenticationContext.getAuthorizationConsent()
			.getScopes()
			.containsAll(authenticationContext.getAuthorizationRequest().getScopes())) {
			return false;
		}

		return true;
	}

	private static OAuth2Authorization.Builder authorizationBuilder(RegisteredClient registeredClient,
			Authentication principal, OAuth2AuthorizationRequest authorizationRequest) {
		return OAuth2Authorization.withRegisteredClient(registeredClient)
			.principalName(principal.getName())
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.attribute(Principal.class.getName(), principal)
			.attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest);
	}

	private static OAuth2TokenContext createAuthorizationCodeTokenContext(
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			RegisteredClient registeredClient, OAuth2Authorization authorization, Set<String> authorizedScopes) {

		// @formatter:off
		DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal((Authentication) authorizationCodeRequestAuthentication.getPrincipal())
				.authorizationServerContext(AuthorizationServerContextHolder.getContext())
				.tokenType(new OAuth2TokenType(OAuth2ParameterNames.CODE))
				.authorizedScopes(authorizedScopes)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrant(authorizationCodeRequestAuthentication);
		// @formatter:on

		if (authorization != null) {
			tokenContextBuilder.authorization(authorization);
		}

		return tokenContextBuilder.build();
	}

	private static boolean isPrincipalAuthenticated(Authentication principal) {
		return principal != null && !AnonymousAuthenticationToken.class.isAssignableFrom(principal.getClass())
				&& principal.isAuthenticated();
	}

	private static void throwError(String errorCode, String parameterName,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			RegisteredClient registeredClient) {
		throwError(errorCode, parameterName, ERROR_URI, authorizationCodeRequestAuthentication, registeredClient, null);
	}

	private static void throwError(String errorCode, String parameterName, String errorUri,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			RegisteredClient registeredClient, OAuth2AuthorizationRequest authorizationRequest) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri);
		throwError(error, parameterName, authorizationCodeRequestAuthentication, registeredClient,
				authorizationRequest);
	}

	private static void throwError(OAuth2Error error, String parameterName,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			RegisteredClient registeredClient, OAuth2AuthorizationRequest authorizationRequest) {

		String redirectUri = resolveRedirectUri(authorizationCodeRequestAuthentication, authorizationRequest,
				registeredClient);
		if (error.getErrorCode().equals(OAuth2ErrorCodes.INVALID_REQUEST)
				&& (parameterName.equals(OAuth2ParameterNames.CLIENT_ID)
						|| parameterName.equals(OAuth2ParameterNames.STATE))) {
			redirectUri = null; // Prevent redirects
		}

		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				authorizationCodeRequestAuthentication.getAuthorizationUri(),
				authorizationCodeRequestAuthentication.getClientId(),
				(Authentication) authorizationCodeRequestAuthentication.getPrincipal(), redirectUri,
				authorizationCodeRequestAuthentication.getState(), authorizationCodeRequestAuthentication.getScopes(),
				authorizationCodeRequestAuthentication.getAdditionalParameters());

		throw new OAuth2AuthorizationCodeRequestAuthenticationException(error,
				authorizationCodeRequestAuthenticationResult);
	}

	private static String resolveRedirectUri(
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			OAuth2AuthorizationRequest authorizationRequest, RegisteredClient registeredClient) {

		if (authorizationCodeRequestAuthentication != null
				&& StringUtils.hasText(authorizationCodeRequestAuthentication.getRedirectUri())) {
			return authorizationCodeRequestAuthentication.getRedirectUri();
		}
		if (authorizationRequest != null && StringUtils.hasText(authorizationRequest.getRedirectUri())) {
			return authorizationRequest.getRedirectUri();
		}
		if (registeredClient != null) {
			return registeredClient.getRedirectUris().iterator().next();
		}
		return null;
	}

}
