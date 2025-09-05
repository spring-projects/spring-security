/*
 * Copyright 2020-2024 the original author or authors.
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

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation for the Device Authorization Consent
 * used in the OAuth 2.0 Device Authorization Grant.
 *
 * @author Steve Riesenberg
 * @since 1.1
 * @see OAuth2DeviceAuthorizationConsentAuthenticationToken
 * @see OAuth2AuthorizationConsent
 * @see OAuth2DeviceAuthorizationRequestAuthenticationProvider
 * @see OAuth2DeviceVerificationAuthenticationProvider
 * @see OAuth2DeviceCodeAuthenticationProvider
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see OAuth2AuthorizationConsentService
 */
public final class OAuth2DeviceAuthorizationConsentAuthenticationProvider implements AuthenticationProvider {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
	static final OAuth2TokenType STATE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.STATE);

	private final Log logger = LogFactory.getLog(getClass());

	private final RegisteredClientRepository registeredClientRepository;

	private final OAuth2AuthorizationService authorizationService;

	private final OAuth2AuthorizationConsentService authorizationConsentService;

	private Consumer<OAuth2AuthorizationConsentAuthenticationContext> authorizationConsentCustomizer;

	/**
	 * Constructs an {@code OAuth2DeviceAuthorizationConsentAuthenticationProvider} using
	 * the provided parameters.
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 * @param authorizationConsentService the authorization consent service
	 */
	public OAuth2DeviceAuthorizationConsentAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
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
		OAuth2DeviceAuthorizationConsentAuthenticationToken deviceAuthorizationConsentAuthentication = (OAuth2DeviceAuthorizationConsentAuthenticationToken) authentication;

		OAuth2Authorization authorization = this.authorizationService
			.findByToken(deviceAuthorizationConsentAuthentication.getState(), STATE_TOKEN_TYPE);
		if (authorization == null) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved authorization with device authorization consent state");
		}

		// The authorization must be associated to the current principal
		Authentication principal = (Authentication) deviceAuthorizationConsentAuthentication.getPrincipal();
		if (!isPrincipalAuthenticated(principal) || !principal.getName().equals(authorization.getPrincipalName())) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE);
		}

		RegisteredClient registeredClient = this.registeredClientRepository
			.findByClientId(deviceAuthorizationConsentAuthentication.getClientId());
		if (registeredClient == null || !registeredClient.getId().equals(authorization.getRegisteredClientId())) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved registered client");
		}

		Set<String> requestedScopes = authorization.getAttribute(OAuth2ParameterNames.SCOPE);
		Set<String> authorizedScopes = new HashSet<>(deviceAuthorizationConsentAuthentication.getScopes());
		if (!requestedScopes.containsAll(authorizedScopes)) {
			throwError(OAuth2ErrorCodes.INVALID_SCOPE, OAuth2ParameterNames.SCOPE);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Validated device authorization consent request parameters");
		}

		OAuth2AuthorizationConsent currentAuthorizationConsent = this.authorizationConsentService
			.findById(authorization.getRegisteredClientId(), principal.getName());
		Set<String> currentAuthorizedScopes = (currentAuthorizationConsent != null)
				? currentAuthorizationConsent.getScopes() : Collections.emptySet();

		if (!currentAuthorizedScopes.isEmpty()) {
			for (String requestedScope : requestedScopes) {
				if (currentAuthorizedScopes.contains(requestedScope)) {
					authorizedScopes.add(requestedScope);
				}
			}
		}

		OAuth2AuthorizationConsent.Builder authorizationConsentBuilder;
		if (currentAuthorizationConsent != null) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Retrieved existing authorization consent");
			}
			authorizationConsentBuilder = OAuth2AuthorizationConsent.from(currentAuthorizationConsent);
		}
		else {
			authorizationConsentBuilder = OAuth2AuthorizationConsent.withId(authorization.getRegisteredClientId(),
					principal.getName());
		}
		authorizedScopes.forEach(authorizationConsentBuilder::scope);

		if (this.authorizationConsentCustomizer != null) {
			// @formatter:off
			OAuth2AuthorizationConsentAuthenticationContext authorizationConsentAuthenticationContext =
					OAuth2AuthorizationConsentAuthenticationContext.with(deviceAuthorizationConsentAuthentication)
							.authorizationConsent(authorizationConsentBuilder)
							.registeredClient(registeredClient)
							.authorization(authorization)
							.build();
			// @formatter:on
			this.authorizationConsentCustomizer.accept(authorizationConsentAuthenticationContext);
			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Customized authorization consent");
			}
		}

		Set<GrantedAuthority> authorities = new HashSet<>();
		authorizationConsentBuilder.authorities(authorities::addAll);

		OAuth2Authorization.Token<OAuth2DeviceCode> deviceCodeToken = authorization.getToken(OAuth2DeviceCode.class);
		OAuth2Authorization.Token<OAuth2UserCode> userCodeToken = authorization.getToken(OAuth2UserCode.class);

		if (authorities.isEmpty()) {
			// Authorization consent denied (or revoked)
			if (currentAuthorizationConsent != null) {
				this.authorizationConsentService.remove(currentAuthorizationConsent);
				if (this.logger.isTraceEnabled()) {
					this.logger.trace("Revoked authorization consent");
				}
			}
			authorization = OAuth2Authorization.from(authorization)
				.invalidate(deviceCodeToken.getToken())
				.invalidate(userCodeToken.getToken())
				.attributes((attrs) -> attrs.remove(OAuth2ParameterNames.STATE))
				.build();
			this.authorizationService.save(authorization);
			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Invalidated device code and user code because authorization consent was denied");
			}
			throwError(OAuth2ErrorCodes.ACCESS_DENIED, OAuth2ParameterNames.CLIENT_ID);
		}

		OAuth2AuthorizationConsent authorizationConsent = authorizationConsentBuilder.build();
		if (!authorizationConsent.equals(currentAuthorizationConsent)) {
			this.authorizationConsentService.save(authorizationConsent);
			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Saved authorization consent");
			}
		}

		authorization = OAuth2Authorization.from(authorization)
			.authorizedScopes(authorizedScopes)
			.invalidate(userCodeToken.getToken())
			.attributes((attrs) -> attrs.remove(OAuth2ParameterNames.STATE))
			.attributes((attrs) -> attrs.remove(OAuth2ParameterNames.SCOPE))
			.build();
		this.authorizationService.save(authorization);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Saved authorization with authorized scopes");
			// This log is kept separate for consistency with other providers
			this.logger.trace("Authenticated device authorization consent request");
		}

		return new OAuth2DeviceVerificationAuthenticationToken(principal,
				deviceAuthorizationConsentAuthentication.getUserCode(), registeredClient.getClientId());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2DeviceAuthorizationConsentAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * Sets the {@code Consumer} providing access to the
	 * {@link OAuth2AuthorizationConsentAuthenticationContext} containing an
	 * {@link OAuth2AuthorizationConsent.Builder} and additional context information.
	 *
	 * <p>
	 * The following context attributes are available:
	 * <ul>
	 * <li>The {@link OAuth2AuthorizationConsent.Builder} used to build the authorization
	 * consent prior to
	 * {@link OAuth2AuthorizationConsentService#save(OAuth2AuthorizationConsent)}.</li>
	 * <li>The {@link Authentication} of type
	 * {@link OAuth2DeviceAuthorizationConsentAuthenticationToken}.</li>
	 * <li>The {@link RegisteredClient} associated with the device authorization
	 * request.</li>
	 * <li>The {@link OAuth2Authorization} associated with the state token presented in
	 * the device authorization consent request.</li>
	 * </ul>
	 * @param authorizationConsentCustomizer the {@code Consumer} providing access to the
	 * {@link OAuth2AuthorizationConsentAuthenticationContext} containing an
	 * {@link OAuth2AuthorizationConsent.Builder}
	 */
	public void setAuthorizationConsentCustomizer(
			Consumer<OAuth2AuthorizationConsentAuthenticationContext> authorizationConsentCustomizer) {
		Assert.notNull(authorizationConsentCustomizer, "authorizationConsentCustomizer cannot be null");
		this.authorizationConsentCustomizer = authorizationConsentCustomizer;
	}

	private static boolean isPrincipalAuthenticated(Authentication principal) {
		return principal != null && !AnonymousAuthenticationToken.class.isAssignableFrom(principal.getClass())
				&& principal.isAuthenticated();
	}

	private static void throwError(String errorCode, String parameterName) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, ERROR_URI);
		throw new OAuth2AuthenticationException(error);
	}

}
