/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client;

import java.io.Serializable;

import org.springframework.lang.Nullable;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.util.Assert;

/**
 * A representation of an OAuth 2.0 &quot;Authorized Client&quot;.
 * <p>
 * A client is considered &quot;authorized&quot; when the End-User (Resource Owner) has
 * granted authorization to the client to access it's protected resources.
 * <p>
 * This class associates the {@link #getClientRegistration() Client} to the
 * {@link #getAccessToken() Access Token} granted/authorized by the
 * {@link #getPrincipalName() Resource Owner}.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see ClientRegistration
 * @see OAuth2AccessToken
 * @see OAuth2RefreshToken
 */
public class OAuth2AuthorizedClient implements Serializable {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final ClientRegistration clientRegistration;

	private final String principalName;

	private final OAuth2AccessToken accessToken;

	private final OAuth2RefreshToken refreshToken;

	/**
	 * Constructs an {@code OAuth2AuthorizedClient} using the provided parameters.
	 * @param clientRegistration the authorized client's registration
	 * @param principalName the name of the End-User {@code Principal} (Resource Owner)
	 * @param accessToken the access token credential granted
	 */
	public OAuth2AuthorizedClient(ClientRegistration clientRegistration, String principalName,
			OAuth2AccessToken accessToken) {
		this(clientRegistration, principalName, accessToken, null);
	}

	/**
	 * Constructs an {@code OAuth2AuthorizedClient} using the provided parameters.
	 * @param clientRegistration the authorized client's registration
	 * @param principalName the name of the End-User {@code Principal} (Resource Owner)
	 * @param accessToken the access token credential granted
	 * @param refreshToken the refresh token credential granted
	 */
	public OAuth2AuthorizedClient(ClientRegistration clientRegistration, String principalName,
			OAuth2AccessToken accessToken, @Nullable OAuth2RefreshToken refreshToken) {
		Assert.notNull(clientRegistration, "clientRegistration cannot be null");
		Assert.hasText(principalName, "principalName cannot be empty");
		Assert.notNull(accessToken, "accessToken cannot be null");
		this.clientRegistration = clientRegistration;
		this.principalName = principalName;
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
	}

	/**
	 * Returns the authorized client's {@link ClientRegistration registration}.
	 * @return the {@link ClientRegistration}
	 */
	public ClientRegistration getClientRegistration() {
		return this.clientRegistration;
	}

	/**
	 * Returns the End-User's {@code Principal} name.
	 * @return the End-User's {@code Principal} name
	 */
	public String getPrincipalName() {
		return this.principalName;
	}

	/**
	 * Returns the {@link OAuth2AccessToken access token} credential granted.
	 * @return the {@link OAuth2AccessToken}
	 */
	public OAuth2AccessToken getAccessToken() {
		return this.accessToken;
	}

	/**
	 * Returns the {@link OAuth2RefreshToken refresh token} credential granted.
	 * @return the {@link OAuth2RefreshToken}
	 * @since 5.1
	 */
	public @Nullable OAuth2RefreshToken getRefreshToken() {
		return this.refreshToken;
	}

}
