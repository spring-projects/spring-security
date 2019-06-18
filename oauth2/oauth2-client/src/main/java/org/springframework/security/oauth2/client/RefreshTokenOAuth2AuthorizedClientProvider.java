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
import org.springframework.security.oauth2.client.endpoint.DefaultRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * An implementation of an {@link OAuth2AuthorizedClientProvider}
 * for the {@link AuthorizationGrantType#REFRESH_TOKEN refresh_token} grant.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see OAuth2AuthorizedClientProvider
 * @see DefaultRefreshTokenTokenResponseClient
 */
public final class RefreshTokenOAuth2AuthorizedClientProvider implements OAuth2AuthorizedClientProvider {
	/**
	 * The name of the {@link OAuth2AuthorizationContext#getAttribute(String) attribute}
	 * in the {@link OAuth2AuthorizationContext context} associated to the value for the "requested scope(s)".
	 * The value of the attribute is a space-delimited or comma-delimited {@code String} of scope(s)
	 * to be requested by the {@link OAuth2AuthorizationContext#getClientRegistration() client}.
	 */
	public static final String REQUEST_SCOPE_ATTRIBUTE_NAME = "org.springframework.security.oauth2.client.REQUEST_SCOPE";

	private OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> accessTokenResponseClient =
			new DefaultRefreshTokenTokenResponseClient();

	/**
	 * Attempt to re-authorize the {@link OAuth2AuthorizationContext#getClientRegistration() client} in the provided {@code context}.
	 * Returns {@code null} if re-authorization is not supported,
	 * e.g. the {@link OAuth2AuthorizedClient#getRefreshToken() refresh token} is not available for the
	 * {@link OAuth2AuthorizationContext#getAuthorizedClient() authorized client}.
	 *
	 * @param context the context that holds authorization-specific state for the client
	 * @return the {@link OAuth2AuthorizedClient} or {@code null} if re-authorization is not supported
	 */
	@Override
	@Nullable
	public OAuth2AuthorizedClient authorize(OAuth2AuthorizationContext context) {
		Assert.notNull(context, "context cannot be null");
		if (!context.reauthorizationRequested() || context.getAuthorizedClient().getRefreshToken() == null) {
			return null;
		}

		String requestScope = context.getAttribute(REQUEST_SCOPE_ATTRIBUTE_NAME);
		Set<String> scopes = null;
		if (!StringUtils.isEmpty(requestScope)) {
			String delimiter = requestScope.indexOf(',') != -1 ? "," : " ";
			scopes = Arrays.stream(StringUtils.delimitedListToStringArray(requestScope, delimiter, " ")).collect(Collectors.toSet());
		}

		OAuth2RefreshTokenGrantRequest refreshTokenGrantRequest =
				new OAuth2RefreshTokenGrantRequest(context.getAuthorizedClient(), scopes);
		OAuth2AccessTokenResponse tokenResponse =
				this.accessTokenResponseClient.getTokenResponse(refreshTokenGrantRequest);

		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				context.getClientRegistration(),
				context.getPrincipal().getName(),
				tokenResponse.getAccessToken(),
				tokenResponse.getRefreshToken());

		return authorizedClient;
	}

	/**
	 * Sets the client used when requesting an access token credential at the Token Endpoint for the {@code refresh_token} grant.
	 *
	 * @param accessTokenResponseClient the client used when requesting an access token credential at the Token Endpoint for the {@code refresh_token} grant
	 */
	public void setAccessTokenResponseClient(OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> accessTokenResponseClient) {
		Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
		this.accessTokenResponseClient = accessTokenResponseClient;
	}
}
