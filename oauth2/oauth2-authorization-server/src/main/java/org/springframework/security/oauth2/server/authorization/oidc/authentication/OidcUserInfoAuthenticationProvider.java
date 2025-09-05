/*
 * Copyright 2020-2022 the original author or authors.
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

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation for OpenID Connect 1.0 UserInfo
 * Endpoint.
 *
 * @author Steve Riesenberg
 * @since 0.2.1
 * @see OAuth2AuthorizationService
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">5.3.
 * UserInfo Endpoint</a>
 */
public final class OidcUserInfoAuthenticationProvider implements AuthenticationProvider {

	private final Log logger = LogFactory.getLog(getClass());

	private final OAuth2AuthorizationService authorizationService;

	private Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper = new DefaultOidcUserInfoMapper();

	/**
	 * Constructs an {@code OidcUserInfoAuthenticationProvider} using the provided
	 * parameters.
	 * @param authorizationService the authorization service
	 */
	public OidcUserInfoAuthenticationProvider(OAuth2AuthorizationService authorizationService) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.authorizationService = authorizationService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OidcUserInfoAuthenticationToken userInfoAuthentication = (OidcUserInfoAuthenticationToken) authentication;

		AbstractOAuth2TokenAuthenticationToken<?> accessTokenAuthentication = null;
		if (AbstractOAuth2TokenAuthenticationToken.class
			.isAssignableFrom(userInfoAuthentication.getPrincipal().getClass())) {
			accessTokenAuthentication = (AbstractOAuth2TokenAuthenticationToken<?>) userInfoAuthentication
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

		if (!authorizedAccessToken.getToken().getScopes().contains(OidcScopes.OPENID)) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INSUFFICIENT_SCOPE);
		}

		OAuth2Authorization.Token<OidcIdToken> idToken = authorization.getToken(OidcIdToken.class);
		if (idToken == null) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Validated user info request");
		}

		OidcUserInfoAuthenticationContext authenticationContext = OidcUserInfoAuthenticationContext
			.with(userInfoAuthentication)
			.accessToken(authorizedAccessToken.getToken())
			.authorization(authorization)
			.build();
		OidcUserInfo userInfo = this.userInfoMapper.apply(authenticationContext);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Authenticated user info request");
		}

		return new OidcUserInfoAuthenticationToken(accessTokenAuthentication, userInfo);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OidcUserInfoAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * Sets the {@link Function} used to extract claims from
	 * {@link OidcUserInfoAuthenticationContext} to an instance of {@link OidcUserInfo}
	 * for the UserInfo response.
	 *
	 * <p>
	 * The {@link OidcUserInfoAuthenticationContext} gives the mapper access to the
	 * {@link OidcUserInfoAuthenticationToken}, as well as, the following context
	 * attributes:
	 * <ul>
	 * <li>{@link OidcUserInfoAuthenticationContext#getAccessToken()} containing the
	 * bearer token used to make the request.</li>
	 * <li>{@link OidcUserInfoAuthenticationContext#getAuthorization()} containing the
	 * {@link OidcIdToken} and {@link OAuth2AccessToken} associated with the bearer token
	 * used to make the request.</li>
	 * </ul>
	 * @param userInfoMapper the {@link Function} used to extract claims from
	 * {@link OidcUserInfoAuthenticationContext} to an instance of {@link OidcUserInfo}
	 */
	public void setUserInfoMapper(Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper) {
		Assert.notNull(userInfoMapper, "userInfoMapper cannot be null");
		this.userInfoMapper = userInfoMapper;
	}

	private static final class DefaultOidcUserInfoMapper
			implements Function<OidcUserInfoAuthenticationContext, OidcUserInfo> {

		// @formatter:off
		private static final List<String> EMAIL_CLAIMS = Arrays.asList(
				StandardClaimNames.EMAIL,
				StandardClaimNames.EMAIL_VERIFIED
		);
		private static final List<String> PHONE_CLAIMS = Arrays.asList(
				StandardClaimNames.PHONE_NUMBER,
				StandardClaimNames.PHONE_NUMBER_VERIFIED
		);
		private static final List<String> PROFILE_CLAIMS = Arrays.asList(
				StandardClaimNames.NAME,
				StandardClaimNames.FAMILY_NAME,
				StandardClaimNames.GIVEN_NAME,
				StandardClaimNames.MIDDLE_NAME,
				StandardClaimNames.NICKNAME,
				StandardClaimNames.PREFERRED_USERNAME,
				StandardClaimNames.PROFILE,
				StandardClaimNames.PICTURE,
				StandardClaimNames.WEBSITE,
				StandardClaimNames.GENDER,
				StandardClaimNames.BIRTHDATE,
				StandardClaimNames.ZONEINFO,
				StandardClaimNames.LOCALE,
				StandardClaimNames.UPDATED_AT
		);
		// @formatter:on

		@Override
		public OidcUserInfo apply(OidcUserInfoAuthenticationContext authenticationContext) {
			OAuth2Authorization authorization = authenticationContext.getAuthorization();
			OidcIdToken idToken = authorization.getToken(OidcIdToken.class).getToken();
			OAuth2AccessToken accessToken = authenticationContext.getAccessToken();
			Map<String, Object> scopeRequestedClaims = getClaimsRequestedByScope(idToken.getClaims(),
					accessToken.getScopes());

			return new OidcUserInfo(scopeRequestedClaims);
		}

		private static Map<String, Object> getClaimsRequestedByScope(Map<String, Object> claims,
				Set<String> requestedScopes) {
			Set<String> scopeRequestedClaimNames = new HashSet<>(32);
			scopeRequestedClaimNames.add(StandardClaimNames.SUB);

			if (requestedScopes.contains(OidcScopes.ADDRESS)) {
				scopeRequestedClaimNames.add(StandardClaimNames.ADDRESS);
			}
			if (requestedScopes.contains(OidcScopes.EMAIL)) {
				scopeRequestedClaimNames.addAll(EMAIL_CLAIMS);
			}
			if (requestedScopes.contains(OidcScopes.PHONE)) {
				scopeRequestedClaimNames.addAll(PHONE_CLAIMS);
			}
			if (requestedScopes.contains(OidcScopes.PROFILE)) {
				scopeRequestedClaimNames.addAll(PROFILE_CLAIMS);
			}

			Map<String, Object> requestedClaims = new HashMap<>(claims);
			requestedClaims.keySet().removeIf((claimName) -> !scopeRequestedClaimNames.contains(claimName));

			return requestedClaims;
		}

	}

}
