/*
 * Copyright 2002-2020 the original author or authors.
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

import java.util.Set;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.CollectionUtils;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * An implementation of a {@link ReactiveOAuth2AccessTokenResponseClient} for the
 * {@link AuthorizationGrantType#REFRESH_TOKEN refresh_token} grant. This implementation
 * uses {@link WebClient} when requesting an access token credential at the Authorization
 * Server's Token Endpoint.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see ReactiveOAuth2AccessTokenResponseClient
 * @see OAuth2RefreshTokenGrantRequest
 * @see OAuth2AccessTokenResponse
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-6">Section 6
 * Refreshing an Access Token</a>
 */
public final class WebClientReactiveRefreshTokenTokenResponseClient
		extends AbstractWebClientReactiveOAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> {

	@Override
	ClientRegistration clientRegistration(OAuth2RefreshTokenGrantRequest grantRequest) {
		return grantRequest.getClientRegistration();
	}

	@Override
	Set<String> scopes(OAuth2RefreshTokenGrantRequest grantRequest) {
		return grantRequest.getScopes();
	}

	@Override
	Set<String> defaultScopes(OAuth2RefreshTokenGrantRequest grantRequest) {
		return grantRequest.getAccessToken().getScopes();
	}

	@Override
	BodyInserters.FormInserter<String> populateTokenRequestBody(OAuth2RefreshTokenGrantRequest grantRequest,
			BodyInserters.FormInserter<String> body) {
		return super.populateTokenRequestBody(grantRequest, body).with(OAuth2ParameterNames.REFRESH_TOKEN,
				grantRequest.getRefreshToken().getTokenValue());
	}

	@Override
	OAuth2AccessTokenResponse populateTokenResponse(OAuth2RefreshTokenGrantRequest grantRequest,
			OAuth2AccessTokenResponse accessTokenResponse) {

		if (!CollectionUtils.isEmpty(accessTokenResponse.getAccessToken().getScopes())
				&& accessTokenResponse.getRefreshToken() != null) {
			return accessTokenResponse;
		}

		OAuth2AccessTokenResponse.Builder tokenResponseBuilder = OAuth2AccessTokenResponse
				.withResponse(accessTokenResponse);
		if (CollectionUtils.isEmpty(accessTokenResponse.getAccessToken().getScopes())) {
			tokenResponseBuilder.scopes(defaultScopes(grantRequest));
		}
		if (accessTokenResponse.getRefreshToken() == null) {
			// Reuse existing refresh token
			tokenResponseBuilder.refreshToken(grantRequest.getRefreshToken().getTokenValue());
		}
		return tokenResponseBuilder.build();
	}

}
