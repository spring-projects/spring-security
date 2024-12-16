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

import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.CollectionUtils;

/**
 * An implementation of {@link OAuth2AccessTokenResponseClient} that &quot;exchanges&quot;
 * a refresh token for an access token at the Authorization Server's Token Endpoint.
 *
 * @author Steve Riesenberg
 * @since 6.4
 * @see OAuth2AccessTokenResponseClient
 * @see OAuth2RefreshTokenGrantRequest
 * @see OAuth2AccessTokenResponse
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-6">Section 6
 * Refreshing an Access Token</a>
 */
public final class RestClientRefreshTokenTokenResponseClient
		extends AbstractRestClientOAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> {

	@Override
	public OAuth2AccessTokenResponse getTokenResponse(OAuth2RefreshTokenGrantRequest grantRequest) {
		OAuth2AccessTokenResponse accessTokenResponse = super.getTokenResponse(grantRequest);
		return populateTokenResponse(grantRequest, accessTokenResponse);
	}

	private OAuth2AccessTokenResponse populateTokenResponse(OAuth2RefreshTokenGrantRequest grantRequest,
			OAuth2AccessTokenResponse accessTokenResponse) {
		if (!CollectionUtils.isEmpty(accessTokenResponse.getAccessToken().getScopes())
				&& accessTokenResponse.getRefreshToken() != null) {
			return accessTokenResponse;
		}
		OAuth2AccessTokenResponse.Builder tokenResponseBuilder = OAuth2AccessTokenResponse
			.withResponse(accessTokenResponse);
		if (CollectionUtils.isEmpty(accessTokenResponse.getAccessToken().getScopes())) {
			tokenResponseBuilder.scopes(grantRequest.getAccessToken().getScopes());
		}
		if (accessTokenResponse.getRefreshToken() == null) {
			// Reuse existing refresh token
			tokenResponseBuilder.refreshToken(grantRequest.getRefreshToken().getTokenValue());
		}
		return tokenResponseBuilder.build();
	}

}
