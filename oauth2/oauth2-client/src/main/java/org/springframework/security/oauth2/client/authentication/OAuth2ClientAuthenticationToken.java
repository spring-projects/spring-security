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
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.util.Collections;
import java.util.Set;

/**
 * An implementation of an {@link AbstractAuthenticationToken}
 * that represents an <i>OAuth 2.0 Client</i> {@link Authentication}.
 *
 * <p>
 * A client is considered <i>&quot;authenticated&quot;</i>,
 * if it receives a successful response from the <i>Token Endpoint</i>.
 * This {@link Authentication} associates the client identified in {@link #getClientRegistration()}
 * to the {@link #getAccessToken()} granted by the resource owner.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see ClientRegistration
 * @see AccessToken
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-5.1">Section 5.1 Access Token Response</a>
 */
public class OAuth2ClientAuthenticationToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	private final ClientRegistration clientRegistration;
	private final AccessToken accessToken;

	public OAuth2ClientAuthenticationToken(ClientRegistration clientRegistration, AccessToken accessToken) {
		super(Collections.emptyList());
		Assert.notNull(clientRegistration, "clientRegistration cannot be null");
		Assert.notNull(accessToken, "accessToken cannot be null");
		this.clientRegistration = clientRegistration;
		this.accessToken = accessToken;
		this.setAuthenticated(true);		// The Client is authenticated by the Authorization Server
	}

	@Override
	public Object getPrincipal() {
		return this.getClientRegistration().getClientId();
	}

	@Override
	public Object getCredentials() {
		return "";		// No need to expose this.getClientRegistration().getClientSecret()
	}

	public ClientRegistration getClientRegistration() {
		return this.clientRegistration;
	}

	public AccessToken getAccessToken() {
		return this.accessToken;
	}

	public final Set<String> getAuthorizedScope() {
		// As per spec, in section 5.1 Successful Access Token Response
		// https://tools.ietf.org/html/rfc6749#section-5.1
		// If AccessToken.scope is empty, then default to the scope
		// originally requested by the client in the Authorization Request
		return (CollectionUtils.isEmpty(this.getAccessToken().getScope()) ?
			this.getClientRegistration().getScope() :
			this.getAccessToken().getScope());
	}
}
