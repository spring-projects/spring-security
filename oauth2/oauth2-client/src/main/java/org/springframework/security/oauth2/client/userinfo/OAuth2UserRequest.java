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
package org.springframework.security.oauth2.client.userinfo;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.Assert;

/**
 * Represents a request the {@link OAuth2UserService} uses
 * when initiating a request to the UserInfo Endpoint.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see ClientRegistration
 * @see OAuth2AccessToken
 * @see OAuth2UserService
 */
public class OAuth2UserRequest {
	private final ClientRegistration clientRegistration;
	private final OAuth2AccessTokenResponse accessTokenResponse;

	/**
	 * Constructs an {@code OAuth2UserRequest} using the provided parameters.
	 *
	 * @param clientRegistration the client registration
	 * @param accessTokenResponse the access token
	 */
	public OAuth2UserRequest(ClientRegistration clientRegistration, OAuth2AccessTokenResponse accessTokenResponse) {
		Assert.notNull(clientRegistration, "clientRegistration cannot be null");
		Assert.notNull(accessTokenResponse, "accessToken cannot be null");
		this.clientRegistration = clientRegistration;
		this.accessTokenResponse = accessTokenResponse;
	}

	/**
	 * Returns the {@link ClientRegistration client registration}.
	 *
	 * @return the {@link ClientRegistration}
	 */
	public ClientRegistration getClientRegistration() {
		return this.clientRegistration;
	}

	/**
	 * Returns an {@link OAuth2AccessTokenResponse} that contains the {@link OAuth2AccessTokenResponse#getAccessToken() access token} credential
	 *
	 * @return the {@link OAuth2AccessTokenResponse}
	 */
	public OAuth2AccessTokenResponse getAccessTokenResponse() {
		return accessTokenResponse;
	}
}
