/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.oauth2.client.endpoint;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * An OAuth 2.0 Refresh Token Grant request that holds the {@link OAuth2RefreshToken
 * refresh token} credential granted to the {@link #getClientRegistration() client}.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see AbstractOAuth2AuthorizationGrantRequest
 * @see OAuth2RefreshToken
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-6">Section 6
 * Refreshing an Access Token</a>
 */
public class OAuth2RefreshTokenGrantRequest extends AbstractOAuth2AuthorizationGrantRequest {

	private final OAuth2AccessToken accessToken;

	private final OAuth2RefreshToken refreshToken;

	private final Set<String> scopes;

	/**
	 * Constructs an {@code OAuth2RefreshTokenGrantRequest} using the provided parameters.
	 * @param clientRegistration the authorized client's registration
	 * @param accessToken the access token credential granted
	 * @param refreshToken the refresh token credential granted
	 */
	public OAuth2RefreshTokenGrantRequest(ClientRegistration clientRegistration, OAuth2AccessToken accessToken,
			OAuth2RefreshToken refreshToken) {
		this(clientRegistration, accessToken, refreshToken, Collections.emptySet());
	}

	/**
	 * Constructs an {@code OAuth2RefreshTokenGrantRequest} using the provided parameters.
	 * @param clientRegistration the authorized client's registration
	 * @param accessToken the access token credential granted
	 * @param refreshToken the refresh token credential granted
	 * @param scopes the scopes to request
	 */
	public OAuth2RefreshTokenGrantRequest(ClientRegistration clientRegistration, OAuth2AccessToken accessToken,
			OAuth2RefreshToken refreshToken, Set<String> scopes) {
		super(AuthorizationGrantType.REFRESH_TOKEN, clientRegistration);
		Assert.notNull(accessToken, "accessToken cannot be null");
		Assert.notNull(refreshToken, "refreshToken cannot be null");
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
		this.scopes = Collections
			.unmodifiableSet((scopes != null) ? new LinkedHashSet<>(scopes) : Collections.emptySet());
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
	 */
	public OAuth2RefreshToken getRefreshToken() {
		return this.refreshToken;
	}

	/**
	 * Returns the scope(s) to request.
	 * @return the scope(s) to request
	 */
	public Set<String> getScopes() {
		return this.scopes;
	}

	/**
	 * Populate default parameters for the Refresh Token Grant.
	 * @param grantRequest the authorization grant request
	 * @return a {@link MultiValueMap} of the parameters used in the OAuth 2.0 Access
	 * Token Request body
	 */
	static MultiValueMap<String, String> defaultParameters(OAuth2RefreshTokenGrantRequest grantRequest) {
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		if (!CollectionUtils.isEmpty(grantRequest.getScopes())) {
			parameters.set(OAuth2ParameterNames.SCOPE,
					StringUtils.collectionToDelimitedString(grantRequest.getScopes(), " "));
		}
		parameters.set(OAuth2ParameterNames.REFRESH_TOKEN, grantRequest.getRefreshToken().getTokenValue());
		return parameters;
	}

}
