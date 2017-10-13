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
import org.springframework.security.oauth2.client.registration.ClientRegistrationIdentifierStrategy;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.oidc.client.authentication.OidcClientAuthenticationToken;
import org.springframework.security.oauth2.oidc.client.authentication.OidcUserAuthenticationToken;
import org.springframework.security.oauth2.oidc.client.authentication.userinfo.OidcUserService;
import org.springframework.security.oauth2.oidc.core.user.OidcUser;
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
 * @see OidcUserAuthenticationToken
 * @see OAuth2ClientAuthenticationToken
 * @see OidcClientAuthenticationToken
 * @see OAuth2UserService
 * @see OidcUserService
 * @see OAuth2User
 * @see OidcUser
 */
public class OAuth2UserAuthenticationProvider implements AuthenticationProvider {
	private final ClientRegistrationIdentifierStrategy<String> providerIdentifierStrategy = new ProviderIdentifierStrategy();
	private final OAuth2UserService userService;
	private GrantedAuthoritiesMapper authoritiesMapper = (authorities -> authorities);

	public OAuth2UserAuthenticationProvider(OAuth2UserService userService) {
		Assert.notNull(userService, "userService cannot be null");
		this.userService = userService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2UserAuthenticationToken userAuthentication = (OAuth2UserAuthenticationToken) authentication;
		OAuth2ClientAuthenticationToken clientAuthentication = userAuthentication.getClientAuthentication();

		if (this.userAuthenticated() && this.userAuthenticatedSameProviderAs(clientAuthentication)) {
			// Create a new user authentication (using same principal)
			// but with a different client authentication association
			return this.createUserAuthentication(
				(OAuth2UserAuthenticationToken)SecurityContextHolder.getContext().getAuthentication(),
				clientAuthentication);
		}

		OAuth2User oauth2User = this.userService.loadUser(clientAuthentication);

		Collection<? extends GrantedAuthority> mappedAuthorities =
				this.authoritiesMapper.mapAuthorities(oauth2User.getAuthorities());

		OAuth2UserAuthenticationToken authenticationResult;
		if (OidcUser.class.isAssignableFrom(oauth2User.getClass())) {
			authenticationResult = new OidcUserAuthenticationToken(
				(OidcUser)oauth2User, mappedAuthorities, (OidcClientAuthenticationToken)clientAuthentication);
		} else {
			authenticationResult = new OAuth2UserAuthenticationToken(
				oauth2User, mappedAuthorities, clientAuthentication);
		}
		authenticationResult.setDetails(clientAuthentication.getDetails());

		return authenticationResult;
	}

	public final void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		Assert.notNull(authoritiesMapper, "authoritiesMapper cannot be null");
		this.authoritiesMapper = authoritiesMapper;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2UserAuthenticationToken.class.isAssignableFrom(authentication);
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

		String userProviderId = this.providerIdentifierStrategy.getIdentifier(
			currentUserAuthentication.getClientAuthentication().getClientRegistration());
		String clientProviderId = this.providerIdentifierStrategy.getIdentifier(
			clientAuthentication.getClientRegistration());

		return userProviderId.equals(clientProviderId);
	}

	private OAuth2UserAuthenticationToken createUserAuthentication(
		OAuth2UserAuthenticationToken currentUserAuthentication,
		OAuth2ClientAuthenticationToken newClientAuthentication) {

		if (OidcUserAuthenticationToken.class.isAssignableFrom(currentUserAuthentication.getClass())) {
			return new OidcUserAuthenticationToken(
				(OidcUser) currentUserAuthentication.getPrincipal(),
				currentUserAuthentication.getAuthorities(),
				newClientAuthentication);
		} else {
			return new OAuth2UserAuthenticationToken(
				(OAuth2User)currentUserAuthentication.getPrincipal(),
				currentUserAuthentication.getAuthorities(),
				newClientAuthentication);
		}
	}

	private static class ProviderIdentifierStrategy implements ClientRegistrationIdentifierStrategy<String> {

		@Override
		public String getIdentifier(ClientRegistration clientRegistration) {
			StringBuilder builder = new StringBuilder();
			builder.append("[").append(clientRegistration.getProviderDetails().getAuthorizationUri()).append("]");
			builder.append("[").append(clientRegistration.getProviderDetails().getTokenUri()).append("]");
			builder.append("[").append(clientRegistration.getProviderDetails().getUserInfoEndpoint().getUri()).append("]");
			return builder.toString();
		}
	}
}
