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

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.util.Set;

/**
 * A representation of an OAuth 2.0 <i>&quot;Authorized Client&quot;</i>.
 * <p>
 * A client is considered <i>&quot;authorized&quot;</i>
 * when it receives a successful response from the <i>Token Endpoint</i>.
 * <p>
 * This class associates the {@link #getClientRegistration() Client}
 * to the {@link #getAccessToken() Access Token}
 * granted/authorized by the {@link #getPrincipalName() Resource Owner}.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see ClientRegistration
 * @see AccessToken
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-5.1">Section 5.1 Access Token Response</a>
 */
public class AuthorizedClient {
	private final ClientRegistration clientRegistration;
	private final String principalName;
	private final AccessToken accessToken;

	public AuthorizedClient(ClientRegistration clientRegistration, String principalName, AccessToken accessToken) {
		Assert.notNull(clientRegistration, "clientRegistration cannot be null");
		Assert.hasText(principalName, "principalName cannot be empty");
		Assert.notNull(accessToken, "accessToken cannot be null");
		this.clientRegistration = clientRegistration;
		this.principalName = principalName;
		this.accessToken = accessToken;
	}

	public ClientRegistration getClientRegistration() {
		return this.clientRegistration;
	}

	public String getPrincipalName() {
		return this.principalName;
	}

	public AccessToken getAccessToken() {
		return this.accessToken;
	}

	public final Set<String> getAuthorizedScopes() {
		// As per spec, in section 5.1 Successful Access Token Response
		// https://tools.ietf.org/html/rfc6749#section-5.1
		// If AccessToken.scopes is empty, then default to the scopes
		// originally requested by the client in the Authorization Request
		return (CollectionUtils.isEmpty(this.getAccessToken().getScopes()) ?
			this.getClientRegistration().getScopes() :
			this.getAccessToken().getScopes());
	}
}
