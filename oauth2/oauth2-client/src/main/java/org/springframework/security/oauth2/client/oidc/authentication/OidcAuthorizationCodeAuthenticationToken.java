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
package org.springframework.security.oauth2.client.oidc.authentication;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.util.Assert;

import java.util.Collection;

/**
 * An {@link OAuth2LoginAuthenticationToken} for <i>OpenID Connect 1.0 Authentication</i>,
 * which leverages the <i>Authorization Code Flow</i>.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2LoginAuthenticationToken
 * @see OidcIdToken
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth">3.1 Authorization Code Flow</a>
 */
public class OidcAuthorizationCodeAuthenticationToken extends OAuth2LoginAuthenticationToken {
	private OidcIdToken idToken;

	/**
	 * This constructor should be used when the Authentication Request/Response is complete.
	 *
	 * @param clientRegistration
	 * @param authorizationExchange
	 */
	public OidcAuthorizationCodeAuthenticationToken(ClientRegistration clientRegistration,
													OAuth2AuthorizationExchange authorizationExchange) {

		super(clientRegistration, authorizationExchange);
	}

	/**
	 * This constructor should be used when the Token Request/Response is complete,
	 * which indicates that the Authorization Code Flow has fully completed
	 * and OpenID Connect 1.0 Authentication has been achieved.
	 *
	 * @param principal
	 * @param authorities
	 * @param clientRegistration
	 * @param authorizationExchange
	 * @param accessToken
	 * @param idToken
	 */
	public OidcAuthorizationCodeAuthenticationToken(OidcUser principal,
													Collection<? extends GrantedAuthority> authorities,
													ClientRegistration clientRegistration,
													OAuth2AuthorizationExchange authorizationExchange,
													OAuth2AccessToken accessToken,
													OidcIdToken idToken) {

		super(principal, authorities, clientRegistration, authorizationExchange, accessToken);
		Assert.notNull(idToken, "idToken cannot be null");
		this.idToken = idToken;
	}

	public OidcIdToken getIdToken() {
		return this.idToken;
	}
}
