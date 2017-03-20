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
package org.springframework.security.oauth2.client.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.user.OAuth2UserService;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;

import java.util.Collection;

/**
 * An implementation of an {@link AbstractAuthenticationToken}
 * that represents an <i>OAuth 2.0</i> {@link Authentication}.
 *
 * <p>
 * It associates an {@link OAuth2User}, {@link ClientRegistration} and an {@link AccessToken}.
 * This <code>Authentication</code> is considered <i>&quot;authenticated&quot;</i> if the {@link OAuth2User}
 * is provided in the respective constructor. This typically happens after the {@link OAuth2UserService}
 * retrieves the end-user's (resource owner) attributes from the <i>UserInfo Endpoint</i>.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2User
 * @see ClientRegistration
 * @see AccessToken
 */
public class OAuth2AuthenticationToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	private final OAuth2User principal;
	private final ClientRegistration clientRegistration;
	private final AccessToken accessToken;

	public OAuth2AuthenticationToken(ClientRegistration clientRegistration, AccessToken accessToken) {
		this(null, AuthorityUtils.NO_AUTHORITIES, clientRegistration, accessToken);
	}

	public OAuth2AuthenticationToken(OAuth2User principal, Collection<? extends GrantedAuthority> authorities,
										ClientRegistration clientRegistration, AccessToken accessToken) {

		super(authorities);
		Assert.notNull(clientRegistration, "clientRegistration cannot be null");
		Assert.notNull(accessToken, "accessToken cannot be null");
		this.principal = principal;
		this.clientRegistration = clientRegistration;
		this.accessToken = accessToken;
		this.setAuthenticated(principal != null);
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

	@Override
	public Object getCredentials() {
		// Credentials are never exposed (by the Provider) for an OAuth2 User
		return "";
	}

	public ClientRegistration getClientRegistration() {
		return this.clientRegistration;
	}

	public AccessToken getAccessToken() {
		return this.accessToken;
	}
}
