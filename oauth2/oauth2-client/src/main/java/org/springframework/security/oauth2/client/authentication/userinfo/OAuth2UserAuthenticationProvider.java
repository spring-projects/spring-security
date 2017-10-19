/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.authentication.userinfo;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;

import java.util.Collection;

/**
 * An implementation of an {@link AuthenticationProvider} that is responsible
 * for obtaining the user attributes of the <i>End-User</i> (resource owner)
 * from the <i>UserInfo Endpoint</i> and creating a <code>Principal</code>
 * in the form of an {@link OAuth2User}.
 *
 * <p>
 * The {@link OAuth2UserAuthenticationProvider} uses an {@link OAuth2UserService}
 * for loading the {@link OAuth2User} and then associating it
 * to the returned {@link OAuth2UserAuthenticationToken}.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2UserAuthenticationToken
 * @see OAuth2ClientAuthenticationToken
 * @see OAuth2UserService
 * @see OAuth2User
 */
public class OAuth2UserAuthenticationProvider implements AuthenticationProvider {
	private final OAuth2UserService userService;
	private GrantedAuthoritiesMapper authoritiesMapper = (authorities -> authorities);

	public OAuth2UserAuthenticationProvider(OAuth2UserService userService) {
		Assert.notNull(userService, "userService cannot be null");
		this.userService = userService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2ClientAuthenticationToken clientAuthentication = (OAuth2ClientAuthenticationToken)authentication;

		// Section 3.1.2.1 Authentication Request - http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
		// scope
		// 		REQUIRED. OpenID Connect requests MUST contain the "openid" scope value.
		if (clientAuthentication.getAuthorizedScopes().contains("openid")) {
			// This is an OpenID Connect Authentication Request so return null
			// and let OidcUserAuthenticationProvider handle it instead
			return null;
		}

		if (this.userAuthenticated() && this.userAuthenticatedSameProviderAs(clientAuthentication)) {
			// Create a new user authentication (using same principal)
			// but with a different client authentication association
			OAuth2UserAuthenticationToken currentUserAuthentication =
				(OAuth2UserAuthenticationToken)SecurityContextHolder.getContext().getAuthentication();

			return new OAuth2UserAuthenticationToken(
				(OAuth2User)currentUserAuthentication.getPrincipal(),
				currentUserAuthentication.getAuthorities(),
				clientAuthentication);
		}

		OAuth2User oauth2User = this.userService.loadUser(clientAuthentication);

		Collection<? extends GrantedAuthority> mappedAuthorities =
				this.authoritiesMapper.mapAuthorities(oauth2User.getAuthorities());

		OAuth2UserAuthenticationToken authenticationResult = new OAuth2UserAuthenticationToken(
				oauth2User, mappedAuthorities, clientAuthentication);
		authenticationResult.setDetails(clientAuthentication.getDetails());

		return authenticationResult;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
	}

	public final void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		Assert.notNull(authoritiesMapper, "authoritiesMapper cannot be null");
		this.authoritiesMapper = authoritiesMapper;
	}

	private boolean userAuthenticated() {
		Authentication currentAuthentication = SecurityContextHolder.getContext().getAuthentication();
		return currentAuthentication != null &&
			currentAuthentication instanceof OAuth2UserAuthenticationToken &&
			currentAuthentication.isAuthenticated();
	}

	private boolean userAuthenticatedSameProviderAs(OAuth2ClientAuthenticationToken clientAuthentication) {
		OAuth2UserAuthenticationToken currentUserAuthentication =
			(OAuth2UserAuthenticationToken)SecurityContextHolder.getContext().getAuthentication();

		String userProviderId = this.getProviderIdentifier(
			currentUserAuthentication.getClientAuthentication().getClientRegistration());
		String clientProviderId = this.getProviderIdentifier(
			clientAuthentication.getClientRegistration());

		return userProviderId.equals(clientProviderId);
	}

	private String getProviderIdentifier(ClientRegistration clientRegistration) {
		StringBuilder builder = new StringBuilder();
		builder.append("[").append(clientRegistration.getProviderDetails().getAuthorizationUri()).append("]");
		builder.append("[").append(clientRegistration.getProviderDetails().getTokenUri()).append("]");
		builder.append("[").append(clientRegistration.getProviderDetails().getUserInfoEndpoint().getUri()).append("]");
		return builder.toString();
	}
}
