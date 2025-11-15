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

package org.springframework.security.oauth2.client.oidc.authentication;

import java.time.Duration;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.ApplicationListener;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.event.OAuth2AuthorizedClientRefreshedEvent;
import org.springframework.security.oauth2.client.oidc.authentication.event.OidcUserRefreshedEvent;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * An {@link ApplicationListener} that listens for events of type
 * {@link OAuth2AuthorizedClientRefreshedEvent} and publishes an event of type
 * {@link OidcUserRefreshedEvent} in order to refresh an {@link OidcUser}.
 *
 * @author Steve Riesenberg
 * @since 6.5
 * @see org.springframework.security.oauth2.client.RefreshTokenOAuth2AuthorizedClientProvider
 * @see OAuth2AuthorizedClientRefreshedEvent
 * @see OidcUserRefreshedEvent
 */
public final class OidcAuthorizedClientRefreshedEventListener
		implements ApplicationEventPublisherAware, ApplicationListener<OAuth2AuthorizedClientRefreshedEvent> {

	private static final String INVALID_ID_TOKEN_ERROR_CODE = "invalid_id_token";

	private static final String INVALID_NONCE_ERROR_CODE = "invalid_nonce";

	private static final String REFRESH_TOKEN_RESPONSE_ERROR_URI = "https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse";

	private OAuth2UserService<OidcUserRequest, OidcUser> userService = new OidcUserService();

	private JwtDecoderFactory<ClientRegistration> jwtDecoderFactory = new OidcIdTokenDecoderFactory();

	private GrantedAuthoritiesMapper authoritiesMapper = (authorities) -> authorities;

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
		.getContextHolderStrategy();

	private ApplicationEventPublisher applicationEventPublisher;

	private Duration clockSkew = Duration.ofSeconds(60);

	@Override
	public void onApplicationEvent(OAuth2AuthorizedClientRefreshedEvent event) {
		if (this.applicationEventPublisher == null) {
			return;
		}

		// The response must contain the openid scope
		OAuth2AccessTokenResponse accessTokenResponse = event.getAccessTokenResponse();
		if (!accessTokenResponse.getAccessToken().getScopes().contains(OidcScopes.OPENID)) {
			return;
		}

		// The response must contain an id_token
		Map<String, Object> additionalParameters = accessTokenResponse.getAdditionalParameters();
		if (!StringUtils.hasText((String) additionalParameters.get(OidcParameterNames.ID_TOKEN))) {
			return;
		}

		// The current authentication must be an OAuth2AuthenticationToken
		Authentication authentication = this.securityContextHolderStrategy.getContext().getAuthentication();
		if (!(authentication instanceof OAuth2AuthenticationToken authenticationToken)) {
			// This event listener only handles the default authentication result. If the
			// application customizes the authentication result by not subclassing
			// OAuth2AuthenticationToken, then a custom event handler should be provided.
			return;
		}

		// The current principal must be an OidcUser
		if (!(authenticationToken.getPrincipal() instanceof OidcUser existingOidcUser)) {
			return;
		}

		// The registrationId must match the one used to log in
		ClientRegistration clientRegistration = event.getAuthorizedClient().getClientRegistration();
		if (!authenticationToken.getAuthorizedClientRegistrationId().equals(clientRegistration.getRegistrationId())) {
			return;
		}

		// Refresh the OidcUser and send a user refreshed event
		OidcIdToken idToken = createOidcToken(clientRegistration, accessTokenResponse);
		validateIdToken(existingOidcUser, idToken);
		OidcUserRequest userRequest = new OidcUserRequest(clientRegistration, accessTokenResponse.getAccessToken(),
				idToken, additionalParameters);
		OidcUser oidcUser = this.userService.loadUser(userRequest);
		Collection<? extends GrantedAuthority> mappedAuthorities = this.authoritiesMapper
			.mapAuthorities(oidcUser.getAuthorities());
		OAuth2AuthenticationToken authenticationResult = new OAuth2AuthenticationToken(oidcUser, mappedAuthorities,
				clientRegistration.getRegistrationId());
		authenticationResult.setDetails(authenticationToken.getDetails());
		OidcUserRefreshedEvent oidcUserRefreshedEvent = new OidcUserRefreshedEvent(accessTokenResponse,
				existingOidcUser, oidcUser, authenticationResult);
		this.applicationEventPublisher.publishEvent(oidcUserRefreshedEvent);
	}

	/**
	 * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
	 * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
	 */
	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

	/**
	 * Sets the {@link JwtDecoderFactory} used for {@link OidcIdToken} signature
	 * verification. The factory returns a {@link JwtDecoder} associated to the provided
	 * {@link ClientRegistration}.
	 * @param jwtDecoderFactory the {@link JwtDecoderFactory} used for {@link OidcIdToken}
	 * signature verification
	 */
	public void setJwtDecoderFactory(JwtDecoderFactory<ClientRegistration> jwtDecoderFactory) {
		Assert.notNull(jwtDecoderFactory, "jwtDecoderFactory cannot be null");
		this.jwtDecoderFactory = jwtDecoderFactory;
	}

	/**
	 * Sets the {@link OAuth2UserService} used for obtaining the user attributes of the
	 * End-User from the UserInfo Endpoint.
	 * @param userService the service used for obtaining the user attributes of the
	 * End-User from the UserInfo Endpoint
	 */
	public void setUserService(OAuth2UserService<OidcUserRequest, OidcUser> userService) {
		Assert.notNull(userService, "userService cannot be null");
		this.userService = userService;
	}

	/**
	 * Sets the {@link GrantedAuthoritiesMapper} used for mapping
	 * {@link OidcUser#getAuthorities()}} to a new set of authorities which will be
	 * associated to the {@link OAuth2LoginAuthenticationToken}.
	 * @param authoritiesMapper the {@link GrantedAuthoritiesMapper} used for mapping the
	 * user's authorities
	 */
	public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		Assert.notNull(authoritiesMapper, "authoritiesMapper cannot be null");
		this.authoritiesMapper = authoritiesMapper;
	}

	/**
	 * Sets the {@link ApplicationEventPublisher} to be used.
	 * @param applicationEventPublisher event publisher to be used
	 */
	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		Assert.notNull(applicationEventPublisher, "applicationEventPublisher cannot be null");
		this.applicationEventPublisher = applicationEventPublisher;
	}

	/**
	 * Sets the maximum acceptable clock skew, which is used when checking the
	 * {@link OidcIdToken#getIssuedAt() issuedAt} time. The default is 60 seconds.
	 * @param clockSkew the maximum acceptable clock skew
	 */
	public void setClockSkew(Duration clockSkew) {
		Assert.notNull(clockSkew, "clockSkew cannot be null");
		Assert.isTrue(clockSkew.getSeconds() >= 0, "clockSkew must be >= 0");
		this.clockSkew = clockSkew;
	}

	private OidcIdToken createOidcToken(ClientRegistration clientRegistration,
			OAuth2AccessTokenResponse accessTokenResponse) {
		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(clientRegistration);
		Jwt jwt = getJwt(accessTokenResponse, jwtDecoder);
		return new OidcIdToken(jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), jwt.getClaims());
	}

	private Jwt getJwt(OAuth2AccessTokenResponse accessTokenResponse, JwtDecoder jwtDecoder) {
		try {
			Map<String, Object> parameters = accessTokenResponse.getAdditionalParameters();
			return jwtDecoder.decode((String) parameters.get(OidcParameterNames.ID_TOKEN));
		}
		catch (JwtException ex) {
			OAuth2Error invalidIdTokenError = new OAuth2Error(INVALID_ID_TOKEN_ERROR_CODE, ex.getMessage(), null);
			throw new OAuth2AuthenticationException(invalidIdTokenError, invalidIdTokenError.toString(), ex);
		}
	}

	private void validateIdToken(OidcUser existingOidcUser, OidcIdToken idToken) {
		// OpenID Connect Core 1.0 - Section 12.2 Successful Refresh Response
		// If an ID Token is returned as a result of a token refresh request, the
		// following requirements apply:
		// its iss Claim Value MUST be the same as in the ID Token issued when the
		// original authentication occurred,
		validateIssuer(existingOidcUser, idToken);
		// its sub Claim Value MUST be the same as in the ID Token issued when the
		// original authentication occurred,
		validateSubject(existingOidcUser, idToken);
		// its iat Claim MUST represent the time that the new ID Token is issued,
		validateIssuedAt(existingOidcUser, idToken);
		// its aud Claim Value MUST be the same as in the ID Token issued when the
		// original authentication occurred,
		validateAudience(existingOidcUser, idToken);
		// if the ID Token contains an auth_time Claim, its value MUST represent the time
		// of the original authentication - not the time that the new ID token is issued,
		validateAuthenticatedAt(existingOidcUser, idToken);
		// it SHOULD NOT have a nonce Claim, even when the ID Token issued at the time of
		// the original authentication contained nonce; however, if it is present, its
		// value MUST be the same as in the ID Token issued at the time of the original
		// authentication,
		validateNonce(existingOidcUser, idToken);
	}

	private void validateIssuer(OidcUser existingOidcUser, OidcIdToken idToken) {
		if (!idToken.getIssuer().toString().equals(existingOidcUser.getIdToken().getIssuer().toString())) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_ID_TOKEN_ERROR_CODE, "Invalid issuer",
					REFRESH_TOKEN_RESPONSE_ERROR_URI);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
	}

	private void validateSubject(OidcUser existingOidcUser, OidcIdToken idToken) {
		if (!idToken.getSubject().equals(existingOidcUser.getIdToken().getSubject())) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_ID_TOKEN_ERROR_CODE, "Invalid subject",
					REFRESH_TOKEN_RESPONSE_ERROR_URI);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
	}

	private void validateIssuedAt(OidcUser existingOidcUser, OidcIdToken idToken) {
		if (!idToken.getIssuedAt().isAfter(existingOidcUser.getIdToken().getIssuedAt().minus(this.clockSkew))) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_ID_TOKEN_ERROR_CODE, "Invalid issued at time",
					REFRESH_TOKEN_RESPONSE_ERROR_URI);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
	}

	private void validateAudience(OidcUser existingOidcUser, OidcIdToken idToken) {
		if (!isValidAudience(existingOidcUser, idToken)) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_ID_TOKEN_ERROR_CODE, "Invalid audience",
					REFRESH_TOKEN_RESPONSE_ERROR_URI);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
	}

	private boolean isValidAudience(OidcUser existingOidcUser, OidcIdToken idToken) {
		List<String> idTokenAudiences = idToken.getAudience();
		Set<String> oidcUserAudiences = new HashSet<>(existingOidcUser.getIdToken().getAudience());
		if (idTokenAudiences.size() != oidcUserAudiences.size()) {
			return false;
		}
		for (String audience : idTokenAudiences) {
			if (!oidcUserAudiences.contains(audience)) {
				return false;
			}
		}
		return true;
	}

	private void validateAuthenticatedAt(OidcUser existingOidcUser, OidcIdToken idToken) {
		if (idToken.getAuthenticatedAt() == null) {
			return;
		}

		if (!idToken.getAuthenticatedAt().equals(existingOidcUser.getIdToken().getAuthenticatedAt())) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_ID_TOKEN_ERROR_CODE, "Invalid authenticated at time",
					REFRESH_TOKEN_RESPONSE_ERROR_URI);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
	}

	private void validateNonce(OidcUser existingOidcUser, OidcIdToken idToken) {
		if (!StringUtils.hasText(idToken.getNonce())) {
			return;
		}

		if (!idToken.getNonce().equals(existingOidcUser.getIdToken().getNonce())) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_NONCE_ERROR_CODE, "Invalid nonce",
					REFRESH_TOKEN_RESPONSE_ERROR_URI);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
	}

}
