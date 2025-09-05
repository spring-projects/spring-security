/*
 * Copyright 2020-2023 the original author or authors.
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

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.oidc.converter.RegisteredClientOidcClientRegistrationConverter;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * An {@link AuthenticationProvider} implementation for OpenID Connect 1.0 Dynamic Client
 * Configuration Endpoint.
 *
 * @author Ovidiu Popa
 * @author Joe Grandja
 * @author Rafal Lewczuk
 * @author Dmitriy Dubson
 * @since 0.4.0
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see OidcClientRegistrationAuthenticationToken
 * @see OidcClientRegistrationAuthenticationProvider
 * @see <a href=
 * "https://openid.net/specs/openid-connect-registration-1_0.html#ClientConfigurationEndpoint">4.
 * Client Configuration Endpoint</a>
 */
public final class OidcClientConfigurationAuthenticationProvider implements AuthenticationProvider {

	static final String DEFAULT_CLIENT_CONFIGURATION_AUTHORIZED_SCOPE = "client.read";

	private final Log logger = LogFactory.getLog(getClass());

	private final RegisteredClientRepository registeredClientRepository;

	private final OAuth2AuthorizationService authorizationService;

	private Converter<RegisteredClient, OidcClientRegistration> clientRegistrationConverter;

	/**
	 * Constructs an {@code OidcClientConfigurationAuthenticationProvider} using the
	 * provided parameters.
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 */
	public OidcClientConfigurationAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationService = authorizationService;
		this.clientRegistrationConverter = new RegisteredClientOidcClientRegistrationConverter();
	}

	/**
	 * Sets the {@link Converter} used for converting a {@link RegisteredClient} to an
	 * {@link OidcClientRegistration}.
	 * @param clientRegistrationConverter the {@link Converter} used for converting a
	 * {@link RegisteredClient} to an {@link OidcClientRegistration}
	 * @since 1.2.0
	 */
	public void setClientRegistrationConverter(
			Converter<RegisteredClient, OidcClientRegistration> clientRegistrationConverter) {
		Assert.notNull(clientRegistrationConverter, "clientRegistrationConverter cannot be null");
		this.clientRegistrationConverter = clientRegistrationConverter;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OidcClientRegistrationAuthenticationToken clientRegistrationAuthentication = (OidcClientRegistrationAuthenticationToken) authentication;

		if (!StringUtils.hasText(clientRegistrationAuthentication.getClientId())) {
			// This is not a Client Configuration Request.
			// Return null to allow OidcClientRegistrationAuthenticationProvider to handle
			// it.
			return null;
		}

		// Validate the "registration" access token
		AbstractOAuth2TokenAuthenticationToken<?> accessTokenAuthentication = null;
		if (AbstractOAuth2TokenAuthenticationToken.class
			.isAssignableFrom(clientRegistrationAuthentication.getPrincipal().getClass())) {
			accessTokenAuthentication = (AbstractOAuth2TokenAuthenticationToken<?>) clientRegistrationAuthentication
				.getPrincipal();
		}
		if (accessTokenAuthentication == null || !accessTokenAuthentication.isAuthenticated()) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
		}

		String accessTokenValue = accessTokenAuthentication.getToken().getTokenValue();
		OAuth2Authorization authorization = this.authorizationService.findByToken(accessTokenValue,
				OAuth2TokenType.ACCESS_TOKEN);
		if (authorization == null) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved authorization with access token");
		}

		OAuth2Authorization.Token<OAuth2AccessToken> authorizedAccessToken = authorization.getAccessToken();
		if (!authorizedAccessToken.isActive()) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
		}
		checkScope(authorizedAccessToken, Collections.singleton(DEFAULT_CLIENT_CONFIGURATION_AUTHORIZED_SCOPE));

		return findRegistration(clientRegistrationAuthentication, authorization);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OidcClientRegistrationAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private OidcClientRegistrationAuthenticationToken findRegistration(
			OidcClientRegistrationAuthenticationToken clientRegistrationAuthentication,
			OAuth2Authorization authorization) {

		RegisteredClient registeredClient = this.registeredClientRepository
			.findByClientId(clientRegistrationAuthentication.getClientId());
		if (registeredClient == null) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
		}

		if (!registeredClient.getId().equals(authorization.getRegisteredClientId())) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Validated client configuration request parameters");
		}

		OidcClientRegistration clientRegistration = this.clientRegistrationConverter.convert(registeredClient);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Authenticated client configuration request");
		}

		return new OidcClientRegistrationAuthenticationToken(
				(Authentication) clientRegistrationAuthentication.getPrincipal(), clientRegistration);
	}

	@SuppressWarnings("unchecked")
	private static void checkScope(OAuth2Authorization.Token<OAuth2AccessToken> authorizedAccessToken,
			Set<String> requiredScope) {
		Collection<String> authorizedScope = Collections.emptySet();
		if (authorizedAccessToken.getClaims().containsKey(OAuth2ParameterNames.SCOPE)) {
			authorizedScope = (Collection<String>) authorizedAccessToken.getClaims().get(OAuth2ParameterNames.SCOPE);
		}
		if (!authorizedScope.containsAll(requiredScope)) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INSUFFICIENT_SCOPE);
		}
		else if (authorizedScope.size() != requiredScope.size()) {
			// Restrict the access token to only contain the required scope
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
		}
	}

}
