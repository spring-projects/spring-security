/*
 * Copyright 2002-2025 the original author or authors.
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

import java.util.Map;

import org.springframework.context.ApplicationListener;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.event.OAuth2TokenRefreshedEvent;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.util.Assert;

/**
 * An {@link ApplicationListener} that listens for {@link OAuth2TokenRefreshedEvent}s
 */
public class RefreshOidcIdTokenHandler implements ApplicationListener<OAuth2TokenRefreshedEvent> {

	private static final String MISSING_ID_TOKEN_ERROR_CODE = "missing_id_token";

	private static final String INVALID_ID_TOKEN_ERROR_CODE = "invalid_id_token";

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
		.getContextHolderStrategy();

	private JwtDecoderFactory<ClientRegistration> jwtDecoderFactory = new OidcIdTokenDecoderFactory();

	@Override
	public void onApplicationEvent(OAuth2TokenRefreshedEvent event) {
		OAuth2AuthorizedClient authorizedClient = event.getAuthorizedClient();

		if (!authorizedClient.getClientRegistration().getScopes().contains(OidcScopes.OPENID)) {
			return;
		}

		Authentication authentication = this.securityContextHolderStrategy.getContext().getAuthentication();
		if (!(authentication instanceof OAuth2AuthenticationToken oauth2Authentication)) {
			return;
		}
		if (!(authentication.getPrincipal() instanceof DefaultOidcUser defaultOidcUser)) {
			return;
		}

		OAuth2AccessTokenResponse accessTokenResponse = event.getAccessTokenResponse();

		String idToken = (String) accessTokenResponse.getAdditionalParameters().get(OidcParameterNames.ID_TOKEN);
		if (idToken == null || idToken.isBlank()) {
			OAuth2Error missingIdTokenError = new OAuth2Error(MISSING_ID_TOKEN_ERROR_CODE,
					"ID token is missing in the token response", null);
			throw new OAuth2AuthenticationException(missingIdTokenError, missingIdTokenError.toString());
		}

		ClientRegistration clientRegistration = authorizedClient.getClientRegistration();
		OidcIdToken refreshedOidcToken = createOidcToken(clientRegistration, accessTokenResponse);
		updateSecurityContext(oauth2Authentication, defaultOidcUser, refreshedOidcToken);
	}

	/**
	 * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
	 * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
	 */
	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

	/**
	 * Sets the {@link JwtDecoderFactory} used for {@link OidcIdToken} signature
	 * verification. The factory returns a {@link JwtDecoder} associated to the provided
	 * {@link ClientRegistration}.
	 * @param jwtDecoderFactory the {@link JwtDecoderFactory} used for {@link OidcIdToken}
	 * signature verification
	 */
	public final void setJwtDecoderFactory(JwtDecoderFactory<ClientRegistration> jwtDecoderFactory) {
		Assert.notNull(jwtDecoderFactory, "jwtDecoderFactory cannot be null");
		this.jwtDecoderFactory = jwtDecoderFactory;
	}

	private void updateSecurityContext(OAuth2AuthenticationToken oauth2Authentication, DefaultOidcUser defaultOidcUser,
			OidcIdToken refreshedOidcToken) {
		OidcUser oidcUser = new DefaultOidcUser(defaultOidcUser.getAuthorities(), refreshedOidcToken,
				defaultOidcUser.getUserInfo(), StandardClaimNames.SUB);

		SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
		context.setAuthentication(new OAuth2AuthenticationToken(oidcUser, oidcUser.getAuthorities(),
				oauth2Authentication.getAuthorizedClientRegistrationId()));

		this.securityContextHolderStrategy.setContext(context);
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

}
