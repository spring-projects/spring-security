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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.oidc.converter.OidcClientRegistrationRegisteredClientConverter;
import org.springframework.security.oauth2.server.authorization.oidc.converter.RegisteredClientOidcClientRegistrationConverter;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * An {@link AuthenticationProvider} implementation for OpenID Connect 1.0 Dynamic Client
 * Registration Endpoint.
 *
 * @author Ovidiu Popa
 * @author Joe Grandja
 * @author Rafal Lewczuk
 * @author Dmitriy Dubson
 * @since 7.0
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see OAuth2TokenGenerator
 * @see OidcClientRegistrationAuthenticationToken
 * @see OidcClientConfigurationAuthenticationProvider
 * @see PasswordEncoder
 * @see <a href=
 * "https://openid.net/specs/openid-connect-registration-1_0.html#ClientRegistration">3.
 * Client Registration Endpoint</a>
 */
public final class OidcClientRegistrationAuthenticationProvider implements AuthenticationProvider {

	private static final String ERROR_URI = "https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationError";

	private static final String DEFAULT_CLIENT_REGISTRATION_AUTHORIZED_SCOPE = "client.create";

	private final Log logger = LogFactory.getLog(getClass());

	private final RegisteredClientRepository registeredClientRepository;

	private final OAuth2AuthorizationService authorizationService;

	private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

	private Converter<RegisteredClient, OidcClientRegistration> clientRegistrationConverter;

	private Converter<OidcClientRegistration, RegisteredClient> registeredClientConverter;

	private PasswordEncoder passwordEncoder;

	/**
	 * Constructs an {@code OidcClientRegistrationAuthenticationProvider} using the
	 * provided parameters.
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 * @param tokenGenerator the token generator
	 */
	public OidcClientRegistrationAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService,
			OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationService = authorizationService;
		this.tokenGenerator = tokenGenerator;
		this.clientRegistrationConverter = new RegisteredClientOidcClientRegistrationConverter();
		this.registeredClientConverter = new OidcClientRegistrationRegisteredClientConverter();
		this.passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OidcClientRegistrationAuthenticationToken clientRegistrationAuthentication = (OidcClientRegistrationAuthenticationToken) authentication;

		if (clientRegistrationAuthentication.getClientRegistration() == null) {
			// This is not a Client Registration Request.
			// Return null to allow OidcClientConfigurationAuthenticationProvider to
			// handle it.
			return null;
		}

		// Validate the "initial" access token
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
		return OidcClientRegistrationAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * Sets the {@link Converter} used for converting an {@link OidcClientRegistration} to
	 * a {@link RegisteredClient}.
	 * @param registeredClientConverter the {@link Converter} used for converting an
	 * {@link OidcClientRegistration} to a {@link RegisteredClient}
	 */
	public void setRegisteredClientConverter(
			Converter<OidcClientRegistration, RegisteredClient> registeredClientConverter) {
		Assert.notNull(registeredClientConverter, "registeredClientConverter cannot be null");
		this.registeredClientConverter = registeredClientConverter;
	}

	/**
	 * Sets the {@link Converter} used for converting a {@link RegisteredClient} to an
	 * {@link OidcClientRegistration}.
	 * @param clientRegistrationConverter the {@link Converter} used for converting a
	 * {@link RegisteredClient} to an {@link OidcClientRegistration}
	 */
	public void setClientRegistrationConverter(
			Converter<RegisteredClient, OidcClientRegistration> clientRegistrationConverter) {
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

	private OidcClientRegistrationAuthenticationToken registerClient(
			OidcClientRegistrationAuthenticationToken clientRegistrationAuthentication,
			OAuth2Authorization authorization) {

		if (!isValidRedirectUris(clientRegistrationAuthentication.getClientRegistration().getRedirectUris())) {
			throwInvalidClientRegistration(OAuth2ErrorCodes.INVALID_REDIRECT_URI,
					OidcClientMetadataClaimNames.REDIRECT_URIS);
		}

		if (!isValidRedirectUris(
				clientRegistrationAuthentication.getClientRegistration().getPostLogoutRedirectUris())) {
			throwInvalidClientRegistration("invalid_client_metadata",
					OidcClientMetadataClaimNames.POST_LOGOUT_REDIRECT_URIS);
		}

		if (!isValidTokenEndpointAuthenticationMethod(clientRegistrationAuthentication.getClientRegistration())) {
			throwInvalidClientRegistration("invalid_client_metadata",
					OidcClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD);
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
				// gh-1344 Return the hashed client_secret
				registeredClient = updatedRegisteredClient;
			}
		}
		else {
			this.registeredClientRepository.save(registeredClient);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Saved registered client");
		}

		OAuth2Authorization registeredClientAuthorization = registerAccessToken(registeredClient);

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

		Map<String, Object> clientRegistrationClaims = this.clientRegistrationConverter.convert(registeredClient)
			.getClaims();
		OidcClientRegistration clientRegistration = OidcClientRegistration.withClaims(clientRegistrationClaims)
			.registrationAccessToken(registeredClientAuthorization.getAccessToken().getToken().getTokenValue())
			.build();

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Authenticated client registration request");
		}

		return new OidcClientRegistrationAuthenticationToken(
				(Authentication) clientRegistrationAuthentication.getPrincipal(), clientRegistration);
	}

	private OAuth2Authorization registerAccessToken(RegisteredClient registeredClient) {
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				registeredClient.getClientAuthenticationMethods().iterator().next(),
				registeredClient.getClientSecret());

		Set<String> authorizedScopes = new HashSet<>();
		authorizedScopes
			.add(OidcClientConfigurationAuthenticationProvider.DEFAULT_CLIENT_CONFIGURATION_AUTHORIZED_SCOPE);
		authorizedScopes = Collections.unmodifiableSet(authorizedScopes);

		// @formatter:off
		OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal(clientPrincipal)
				.authorizationServerContext(AuthorizationServerContextHolder.getContext())
				.authorizedScopes(authorizedScopes)
				.tokenType(OAuth2TokenType.ACCESS_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.build();
		// @formatter:on

		OAuth2Token registrationAccessToken = this.tokenGenerator.generate(tokenContext);
		if (registrationAccessToken == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
					"The token generator failed to generate the registration access token.", ERROR_URI);
			throw new OAuth2AuthenticationException(error);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Generated registration access token");
		}

		// @formatter:off
		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(registeredClient.getClientId())
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.authorizedScopes(authorizedScopes);
		// @formatter:on

		OidcAuthenticationProviderUtils.accessToken(authorizationBuilder, registrationAccessToken, tokenContext);

		OAuth2Authorization authorization = authorizationBuilder.build();

		this.authorizationService.save(authorization);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Saved authorization with registration access token");
		}

		return authorization;
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

	private static boolean isValidTokenEndpointAuthenticationMethod(OidcClientRegistration clientRegistration) {
		String authenticationMethod = clientRegistration.getTokenEndpointAuthenticationMethod();
		String authenticationSigningAlgorithm = clientRegistration.getTokenEndpointAuthenticationSigningAlgorithm();

		if (!ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue().equals(authenticationMethod)
				&& !ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue().equals(authenticationMethod)) {
			return !StringUtils.hasText(authenticationSigningAlgorithm);
		}

		if ("none".equals(authenticationSigningAlgorithm)) {
			return false;
		}

		if (ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue().equals(authenticationMethod)) {
			return clientRegistration.getJwkSetUrl() != null && (!StringUtils.hasText(authenticationSigningAlgorithm)
					|| SignatureAlgorithm.from(authenticationSigningAlgorithm) != null);
		}
		else {
			// client_secret_jwt
			return !StringUtils.hasText(authenticationSigningAlgorithm)
					|| MacAlgorithm.from(authenticationSigningAlgorithm) != null;
		}
	}

	private static void throwInvalidClientRegistration(String errorCode, String fieldName) {
		OAuth2Error error = new OAuth2Error(errorCode, "Invalid Client Registration: " + fieldName, ERROR_URI);
		throw new OAuth2AuthenticationException(error);
	}

}
