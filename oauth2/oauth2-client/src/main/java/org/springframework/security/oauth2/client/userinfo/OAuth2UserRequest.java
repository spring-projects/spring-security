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
package org.springframework.security.oauth2.client.userinfo;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.util.Assert;

/**
 * Represents a request the {@link OAuth2UserService} uses
 * when initiating a HTTP request to the <i>UserInfo Endpoint</i>.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see ClientRegistration
 * @see OAuth2AccessToken
 * @see OAuth2UserService
 */
public class OAuth2UserRequest {
	private final ClientRegistration clientRegistration;
	private final OAuth2AccessToken accessToken;

	public OAuth2UserRequest(ClientRegistration clientRegistration, OAuth2AccessToken accessToken) {
		Assert.notNull(clientRegistration, "clientRegistration cannot be null");
		Assert.notNull(accessToken, "accessToken cannot be null");
		this.clientRegistration = clientRegistration;
		this.accessToken = accessToken;
	}

	public ClientRegistration getClientRegistration() {
		return this.clientRegistration;
	}

	public OAuth2AccessToken getAccessToken() {
		return this.accessToken;
	}
}
