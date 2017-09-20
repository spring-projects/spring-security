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
package org.springframework.security.oauth2.oidc.client.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2UserAuthenticationToken;
import org.springframework.security.oauth2.oidc.core.user.OidcUser;

import java.util.Collection;

/**
 * A {@link OAuth2UserAuthenticationToken} that represents an
 * <i>OpenID Connect 1.0 User</i> {@link Authentication}.
 *
 * <p>
 * This {@link Authentication} associates an {@link OidcUser} principal to a
 * {@link OidcClientAuthenticationToken} which represents the <i>&quot;Authorized Client&quot;</i>.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OidcUser
 * @see OidcClientAuthenticationToken
 * @see OAuth2UserAuthenticationToken
 */
public class OidcUserAuthenticationToken extends OAuth2UserAuthenticationToken {

	public OidcUserAuthenticationToken(OidcUser principal, Collection<? extends GrantedAuthority> authorities,
										OidcClientAuthenticationToken clientAuthentication) {
		super(principal, authorities, clientAuthentication);
	}
}
