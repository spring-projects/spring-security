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

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.client.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;

import java.util.Collection;

/**
 * An implementation of an {@link AbstractAuthenticationToken}
 * that represents an <i>OAuth 2.0</i> {@link Authentication}.
 *
 * <p>
 * This {@link Authentication} associates an {@link OAuth2User} principal to an
 * {@link OAuth2ClientAuthenticationToken} which represents the <i>&quot;Authorized Client&quot;</i>.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2User
 * @see OAuth2ClientAuthenticationToken
 */
public class OAuth2AuthenticationToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	private final OAuth2User principal;
	private final OAuth2ClientAuthenticationToken clientAuthentication;

	public OAuth2AuthenticationToken(OAuth2User principal, Collection<? extends GrantedAuthority> authorities,
										OAuth2ClientAuthenticationToken clientAuthentication) {
		super(authorities);
		Assert.notNull(clientAuthentication, "clientAuthentication cannot be null");
		this.principal = principal;
		this.clientAuthentication = clientAuthentication;
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

	public OAuth2ClientAuthenticationToken getClientAuthentication() {
		return this.clientAuthentication;
	}
}
