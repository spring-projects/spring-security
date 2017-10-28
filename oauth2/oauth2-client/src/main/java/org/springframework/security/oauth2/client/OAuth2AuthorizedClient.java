/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.oauth2.client;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.util.Assert;

/**
 * A representation of an OAuth 2.0 <i>&quot;Authorized Client&quot;</i>.
 * <p>
 * A client is considered <i>&quot;authorized&quot;</i> when the End-User (Resource Owner)
 * grants authorization to the Client to access its protected resources.
 * <p>
 * This class associates the {@link #getClientRegistration() Client}
 * to the {@link #getAccessToken() Access Token}
 * granted/authorized by the {@link #getPrincipalName() Resource Owner}.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see ClientRegistration
 * @see OAuth2AccessToken
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-5.1">Section 5.1 Access Token Response</a>
 */
public class OAuth2AuthorizedClient {
	private final ClientRegistration clientRegistration;
	private final String principalName;
	private final OAuth2AccessToken accessToken;

	public OAuth2AuthorizedClient(ClientRegistration clientRegistration, String principalName, OAuth2AccessToken accessToken) {
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

	public OAuth2AccessToken getAccessToken() {
		return this.accessToken;
	}
}
