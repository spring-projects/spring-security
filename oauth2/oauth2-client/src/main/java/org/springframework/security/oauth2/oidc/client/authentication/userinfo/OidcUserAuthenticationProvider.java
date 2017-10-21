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
package org.springframework.security.oauth2.oidc.client.authentication.userinfo;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.oidc.client.authentication.OidcClientAuthenticationToken;
import org.springframework.security.oauth2.oidc.client.authentication.OidcUserAuthenticationToken;
import org.springframework.security.oauth2.oidc.core.user.OidcUser;
import org.springframework.util.Assert;

import java.util.Collection;

/**
 * An implementation of an {@link AuthenticationProvider} that is responsible
 * for obtaining the user attributes of the <i>End-User</i> (resource owner)
 * from the <i>UserInfo Endpoint</i> and creating a <code>Principal</code>
 * in the form of an {@link OidcUser}.
 *
 * <p>
 * The {@link OidcUserAuthenticationProvider} uses an {@link OidcUserService}
 * for loading the {@link OidcUser} and then associating it
 * to the returned {@link OidcUserAuthenticationToken}.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OidcUserAuthenticationToken
 * @see OidcClientAuthenticationToken
 * @see OidcUserService
 * @see OidcUser
 */
public class OidcUserAuthenticationProvider implements AuthenticationProvider {
	private final OAuth2UserService userService;
	private GrantedAuthoritiesMapper authoritiesMapper = (authorities -> authorities);

	public OidcUserAuthenticationProvider(OAuth2UserService userService) {
		Assert.notNull(userService, "userService cannot be null");
		this.userService = userService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OidcClientAuthenticationToken clientAuthentication = (OidcClientAuthenticationToken) authentication;

		if (this.userAuthenticated()) {
			// Create a new user authentication (using same principal)
			// but with a different client authentication association
			OidcUserAuthenticationToken currentUserAuthentication =
				(OidcUserAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

			return new OidcUserAuthenticationToken(
				(OidcUser) currentUserAuthentication.getPrincipal(),
				currentUserAuthentication.getAuthorities(),
				clientAuthentication);
		}

		OAuth2User oauth2User = this.userService.loadUser(clientAuthentication);

		Collection<? extends GrantedAuthority> mappedAuthorities =
				this.authoritiesMapper.mapAuthorities(oauth2User.getAuthorities());

		OidcUserAuthenticationToken authenticationResult = new OidcUserAuthenticationToken(
				(OidcUser)oauth2User, mappedAuthorities, clientAuthentication);
		authenticationResult.setDetails(clientAuthentication.getDetails());

		return authenticationResult;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OidcClientAuthenticationToken.class.isAssignableFrom(authentication);
	}

	public final void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		Assert.notNull(authoritiesMapper, "authoritiesMapper cannot be null");
		this.authoritiesMapper = authoritiesMapper;
	}

	private boolean userAuthenticated() {
		Authentication currentAuthentication = SecurityContextHolder.getContext().getAuthentication();
		return currentAuthentication != null &&
			currentAuthentication instanceof OidcUserAuthenticationToken &&
			currentAuthentication.isAuthenticated();
	}
}
