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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.converter.OAuth2ClientRegistrationRegisteredClientConverter;
import org.springframework.security.oauth2.server.authorization.converter.RegisteredClientOAuth2ClientRegistrationConverter;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Dynamic Client
 * Registration Endpoint.
 *
 * @author Joe Grandja
 * @since 7.0
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see OAuth2ClientRegistrationAuthenticationToken
 * @see PasswordEncoder
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591#section-3">3. Client
 * Registration Endpoint</a>
 */
public final class OAuth2ClientRegistrationAuthenticationProvider implements AuthenticationProvider {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2";

	private static final String DEFAULT_CLIENT_REGISTRATION_AUTHORIZED_SCOPE = "client.create";

	private final Log logger = LogFactory.getLog(getClass());

	private final RegisteredClientRepository registeredClientRepository;

	private final OAuth2AuthorizationService authorizationService;

	private Converter<RegisteredClient, OAuth2ClientRegistration> clientRegistrationConverter;

	private Converter<OAuth2ClientRegistration, RegisteredClient> registeredClientConverter;

	private PasswordEncoder passwordEncoder;

	private boolean openRegistrationAllowed;

	/**
	 * Constructs an {@code OAuth2ClientRegistrationAuthenticationProvider} using the
	 * provided parameters.
	 * @param registeredClientRepository the repository of registered clients
	 */
	public OAuth2ClientRegistrationAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationService = authorizationService;
		this.clientRegistrationConverter = new RegisteredClientOAuth2ClientRegistrationConverter();
		this.registeredClientConverter = new OAuth2ClientRegistrationRegisteredClientConverter();
		this.passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2ClientRegistrationAuthenticationToken clientRegistrationAuthentication = (OAuth2ClientRegistrationAuthenticationToken) authentication;

		// Check if "initial" access token is not provided
		AbstractOAuth2TokenAuthenticationToken<?> accessTokenAuthentication = null;
		if (clientRegistrationAuthentication.getPrincipal() != null && AbstractOAuth2TokenAuthenticationToken.class
			.isAssignableFrom(clientRegistrationAuthentication.getPrincipal().getClass())) {
			accessTokenAuthentication = (AbstractOAuth2TokenAuthenticationToken<?>) clientRegistrationAuthentication
				.getPrincipal();
		}
		if (accessTokenAuthentication == null) {
			if (this.openRegistrationAllowed) {
				return registerClient(clientRegistrationAuthentication, null);
			}
			else {
				throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
			}
		}

		// Validate the "initial" access token
		if (!accessTokenAuthentication.isAuthenticated()) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
		}

		String accessTokenValue = accessTokenAuthentication.getToken().getTokenValue();
		OAuth2Authorization authorization = this.authorizationService.findByToken(accessTokenValue,
				OAuth2TokenType.ACCESS_TOKEN);
		if (authorization == null) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved authorization with initial access token");
		}

		OAuth2Authorization.Token<OAuth2AccessToken> authorizedAccessToken = authorization.getAccessToken();
		if (!authorizedAccessToken.isActive()) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
		}
		checkScope(authorizedAccessToken, Collections.singleton(DEFAULT_CLIENT_REGISTRATION_AUTHORIZED_SCOPE));

		return registerClient(clientRegistrationAuthentication, authorization);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2ClientRegistrationAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * Sets the {@link Converter} used for converting an {@link OAuth2ClientRegistration}
	 * to a {@link RegisteredClient}.
	 * @param registeredClientConverter the {@link Converter} used for converting an
	 * {@link OAuth2ClientRegistration} to a {@link RegisteredClient}
	 */
	public void setRegisteredClientConverter(
			Converter<OAuth2ClientRegistration, RegisteredClient> registeredClientConverter) {
		Assert.notNull(registeredClientConverter, "registeredClientConverter cannot be null");
		this.registeredClientConverter = registeredClientConverter;
	}

	/**
	 * Sets the {@link Converter} used for converting a {@link RegisteredClient} to an
	 * {@link OAuth2ClientRegistration}.
	 * @param clientRegistrationConverter the {@link Converter} used for converting a
	 * {@link RegisteredClient} to an {@link OAuth2ClientRegistration}
	 */
	public void setClientRegistrationConverter(
			Converter<RegisteredClient, OAuth2ClientRegistration> clientRegistrationConverter) {
		Assert.notNull(clientRegistrationConverter, "clientRegistrationConverter cannot be null");
		this.clientRegistrationConverter = clientRegistrationConverter;
	}

	/**
	 * Sets the {@link PasswordEncoder} used to encode the
	 * {@link RegisteredClient#getClientSecret() client secret}. If not set, the client
	 * secret will be encoded using
	 * {@link PasswordEncoderFactories#createDelegatingPasswordEncoder()}.
	 * @param passwordEncoder the {@link PasswordEncoder} used to encode the client secret
	 */
	public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		Assert.notNull(passwordEncoder, "passwordEncoder cannot be null");
		this.passwordEncoder = passwordEncoder;
	}

	/**
	 * Set to {@code true} if open client registration (with no initial access token) is
	 * allowed. The default is {@code false}.
	 * @param openRegistrationAllowed {@code true} if open client registration is allowed,
	 * {@code false} otherwise
	 */
	public void setOpenRegistrationAllowed(boolean openRegistrationAllowed) {
		this.openRegistrationAllowed = openRegistrationAllowed;
	}

	private OAuth2ClientRegistrationAuthenticationToken registerClient(
			OAuth2ClientRegistrationAuthenticationToken clientRegistrationAuthentication,
			OAuth2Authorization authorization) {

		if (!isValidRedirectUris(clientRegistrationAuthentication.getClientRegistration().getRedirectUris())) {
			throwInvalidClientRegistration(OAuth2ErrorCodes.INVALID_REDIRECT_URI,
					OAuth2ClientMetadataClaimNames.REDIRECT_URIS);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Validated client registration request parameters");
		}

		RegisteredClient registeredClient = this.registeredClientConverter
			.convert(clientRegistrationAuthentication.getClientRegistration());

		if (StringUtils.hasText(registeredClient.getClientSecret())) {
			// Encode the client secret
			RegisteredClient updatedRegisteredClient = RegisteredClient.from(registeredClient)
				.clientSecret(this.passwordEncoder.encode(registeredClient.getClientSecret()))
				.build();
			this.registeredClientRepository.save(updatedRegisteredClient);
			if (ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue()
				.equals(clientRegistrationAuthentication.getClientRegistration()
					.getTokenEndpointAuthenticationMethod())) {
				// Return the hashed client_secret
				registeredClient = updatedRegisteredClient;
			}
		}
		else {
			this.registeredClientRepository.save(registeredClient);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Saved registered client");
		}

		if (authorization != null) {
			// Invalidate the "initial" access token as it can only be used once
			OAuth2Authorization.Builder builder = OAuth2Authorization.from(authorization)
				.invalidate(authorization.getAccessToken().getToken());
			if (authorization.getRefreshToken() != null) {
				builder.invalidate(authorization.getRefreshToken().getToken());
			}
			authorization = builder.build();
			this.authorizationService.save(authorization);

			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Saved authorization with invalidated initial access token");
			}
		}

		OAuth2ClientRegistration clientRegistration = this.clientRegistrationConverter.convert(registeredClient);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Authenticated client registration request");
		}

		OAuth2ClientRegistrationAuthenticationToken clientRegistrationAuthenticationResult = new OAuth2ClientRegistrationAuthenticationToken(
				(Authentication) clientRegistrationAuthentication.getPrincipal(), clientRegistration);
		clientRegistrationAuthenticationResult.setDetails(clientRegistrationAuthentication.getDetails());
		return clientRegistrationAuthenticationResult;
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

	private static boolean isValidRedirectUris(List<String> redirectUris) {
		if (CollectionUtils.isEmpty(redirectUris)) {
			return true;
		}

		for (String redirectUri : redirectUris) {
			try {
				URI validRedirectUri = new URI(redirectUri);
				if (validRedirectUri.getFragment() != null) {
					return false;
				}
			}
			catch (URISyntaxException ex) {
				return false;
			}
		}

		return true;
	}

	private static void throwInvalidClientRegistration(String errorCode, String fieldName) {
		OAuth2Error error = new OAuth2Error(errorCode, "Invalid Client Registration: " + fieldName, ERROR_URI);
		throw new OAuth2AuthenticationException(error);
	}

}
