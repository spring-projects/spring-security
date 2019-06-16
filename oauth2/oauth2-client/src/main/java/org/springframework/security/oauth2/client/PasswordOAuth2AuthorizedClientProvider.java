/*
 * Copyright 2002-2019 the original author or authors.
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

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.client.endpoint.DefaultPasswordTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2PasswordGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * An implementation of an {@link OAuth2AuthorizedClientProvider}
 * for the {@link AuthorizationGrantType#PASSWORD password} grant.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see OAuth2AuthorizedClientProvider
 * @see DefaultPasswordTokenResponseClient
 */
public final class PasswordOAuth2AuthorizedClientProvider implements OAuth2AuthorizedClientProvider {
	private OAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> accessTokenResponseClient =
			new DefaultPasswordTokenResponseClient();

	/**
	 * Attempt to authorize the {@link OAuth2AuthorizationContext#getClientRegistration() client} in the provided {@code context}.
	 * Returns {@code null} if authorization is not supported,
	 * e.g. the client's {@link ClientRegistration#getAuthorizationGrantType() authorization grant type}
	 * is not {@link AuthorizationGrantType#PASSWORD password} OR the client is already authorized OR
	 * the {@link OAuth2AuthorizationContext#USERNAME_ATTRIBUTE_NAME username} and/or
	 * {@link OAuth2AuthorizationContext#PASSWORD_ATTRIBUTE_NAME password} attributes
	 * are not available in the provided {@code context}.
	 *
	 * <p>
	 * The following {@link OAuth2AuthorizationContext#getAttributes() context attributes} are supported:
	 * <ol>
	 *  <li>{@link OAuth2AuthorizationContext#USERNAME_ATTRIBUTE_NAME} (required) - a {@code String} value for the resource owner's username</li>
	 *  <li>{@link OAuth2AuthorizationContext#PASSWORD_ATTRIBUTE_NAME} (required) - a {@code String} value for the resource owner's password</li>
	 * </ol>
	 *
	 * @param context the context that holds authorization-specific state for the client
	 * @return the {@link OAuth2AuthorizedClient} or {@code null} if authorization is not supported
	 */
	@Override
	@Nullable
	public OAuth2AuthorizedClient authorize(OAuth2AuthorizationContext context) {
		Assert.notNull(context, "context cannot be null");

		ClientRegistration clientRegistration = context.getClientRegistration();
		OAuth2AuthorizedClient authorizedClient = context.getAuthorizedClient();
		if (!AuthorizationGrantType.PASSWORD.equals(clientRegistration.getAuthorizationGrantType()) ||
				authorizedClient != null) {
			return null;
		}

		String username = context.getAttribute(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME);
		String password = context.getAttribute(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME);
		if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
			return null;
		}

		OAuth2PasswordGrantRequest passwordGrantRequest =
				new OAuth2PasswordGrantRequest(clientRegistration, username, password);
		OAuth2AccessTokenResponse tokenResponse =
				this.accessTokenResponseClient.getTokenResponse(passwordGrantRequest);

		return new OAuth2AuthorizedClient(clientRegistration, context.getPrincipal().getName(),
				tokenResponse.getAccessToken(), tokenResponse.getRefreshToken());
	}

	/**
	 * Sets the client used when requesting an access token credential at the Token Endpoint for the {@code password} grant.
	 *
	 * @param accessTokenResponseClient the client used when requesting an access token credential at the Token Endpoint for the {@code password} grant
	 */
	public void setAccessTokenResponseClient(OAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> accessTokenResponseClient) {
		Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
		this.accessTokenResponseClient = accessTokenResponseClient;
	}
}
