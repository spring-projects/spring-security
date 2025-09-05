/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.authentication;

import java.io.Serial;
import java.util.Collections;
import java.util.Map;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} implementation used when issuing an OAuth 2.0 Access Token
 * and (optional) Refresh Token.
 *
 * @author Joe Grandja
 * @author Madhu Bhat
 * @since 0.0.1
 * @see AbstractAuthenticationToken
 * @see RegisteredClient
 * @see OAuth2AccessToken
 * @see OAuth2RefreshToken
 * @see OAuth2ClientAuthenticationToken
 */
public class OAuth2AccessTokenAuthenticationToken extends AbstractAuthenticationToken {

	@Serial
	private static final long serialVersionUID = 2773767853287774441L;

	private final RegisteredClient registeredClient;

	private final Authentication clientPrincipal;

	private final OAuth2AccessToken accessToken;

	private final OAuth2RefreshToken refreshToken;

	private final Map<String, Object> additionalParameters;

	/**
	 * Constructs an {@code OAuth2AccessTokenAuthenticationToken} using the provided
	 * parameters.
	 * @param registeredClient the registered client
	 * @param clientPrincipal the authenticated client principal
	 * @param accessToken the access token
	 */
	public OAuth2AccessTokenAuthenticationToken(RegisteredClient registeredClient, Authentication clientPrincipal,
			OAuth2AccessToken accessToken) {
		this(registeredClient, clientPrincipal, accessToken, null);
	}

	/**
	 * Constructs an {@code OAuth2AccessTokenAuthenticationToken} using the provided
	 * parameters.
	 * @param registeredClient the registered client
	 * @param clientPrincipal the authenticated client principal
	 * @param accessToken the access token
	 * @param refreshToken the refresh token
	 */
	public OAuth2AccessTokenAuthenticationToken(RegisteredClient registeredClient, Authentication clientPrincipal,
			OAuth2AccessToken accessToken, @Nullable OAuth2RefreshToken refreshToken) {
		this(registeredClient, clientPrincipal, accessToken, refreshToken, Collections.emptyMap());
	}

	/**
	 * Constructs an {@code OAuth2AccessTokenAuthenticationToken} using the provided
	 * parameters.
	 * @param registeredClient the registered client
	 * @param clientPrincipal the authenticated client principal
	 * @param accessToken the access token
	 * @param refreshToken the refresh token
	 * @param additionalParameters the additional parameters
	 */
	public OAuth2AccessTokenAuthenticationToken(RegisteredClient registeredClient, Authentication clientPrincipal,
			OAuth2AccessToken accessToken, @Nullable OAuth2RefreshToken refreshToken,
			Map<String, Object> additionalParameters) {
		super(Collections.emptyList());
		Assert.notNull(registeredClient, "registeredClient cannot be null");
		Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
		Assert.notNull(accessToken, "accessToken cannot be null");
		Assert.notNull(additionalParameters, "additionalParameters cannot be null");
		this.registeredClient = registeredClient;
		this.clientPrincipal = clientPrincipal;
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
		this.additionalParameters = additionalParameters;
	}

	@Override
	public Object getPrincipal() {
		return this.clientPrincipal;
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	/**
	 * Returns the {@link RegisteredClient registered client}.
	 * @return the {@link RegisteredClient}
	 */
	public RegisteredClient getRegisteredClient() {
		return this.registeredClient;
	}

	/**
	 * Returns the {@link OAuth2AccessToken access token}.
	 * @return the {@link OAuth2AccessToken}
	 */
	public OAuth2AccessToken getAccessToken() {
		return this.accessToken;
	}

	/**
	 * Returns the {@link OAuth2RefreshToken refresh token}.
	 * @return the {@link OAuth2RefreshToken} or {@code null} if not available
	 */
	@Nullable
	public OAuth2RefreshToken getRefreshToken() {
		return this.refreshToken;
	}

	/**
	 * Returns the additional parameters.
	 * @return a {@code Map} of the additional parameters, may be empty
	 */
	public Map<String, Object> getAdditionalParameters() {
		return this.additionalParameters;
	}

}
