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

import org.springframework.context.ApplicationListener;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.event.OAuth2TokenRefreshedEvent;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

/**
 * An {@link ApplicationListener} that listens for {@link OAuth2TokenRefreshedEvent}s
 */
public class RefreshOidcIdTokenHandler implements ApplicationListener<OAuth2TokenRefreshedEvent> {

	private final OidcAuthorizationCodeAuthenticationProvider oidcAuthorizationCodeAuthenticationProvider;

	public RefreshOidcIdTokenHandler(
			OidcAuthorizationCodeAuthenticationProvider oidcAuthorizationCodeAuthenticationProvider) {
		this.oidcAuthorizationCodeAuthenticationProvider = oidcAuthorizationCodeAuthenticationProvider;
	}

	@Override
	public void onApplicationEvent(OAuth2TokenRefreshedEvent event) {
		OAuth2AuthorizedClient authorizedClient = event.getAuthorizedClient();
		OAuth2AccessTokenResponse accessTokenResponse = event.getAccessTokenResponse();
		OidcIdToken refreshedOidcToken = this.oidcAuthorizationCodeAuthenticationProvider
			.createOidcToken(authorizedClient.getClientRegistration(), accessTokenResponse);
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication instanceof OAuth2AuthenticationToken oauth2AuthenticationToken) {
			if (authentication.getPrincipal() instanceof DefaultOidcUser defaultOidcUser) {
				OidcUser oidcUser = new DefaultOidcUser(defaultOidcUser.getAuthorities(), refreshedOidcToken,
						defaultOidcUser.getUserInfo(), StandardClaimNames.SUB);
				SecurityContextHolder.getContext()
					.setAuthentication(new OAuth2AuthenticationToken(oidcUser, oidcUser.getAuthorities(),
							oauth2AuthenticationToken.getAuthorizedClientRegistrationId()));
			}
		}
	}

}
