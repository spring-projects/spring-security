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

package org.springframework.security.oauth2.client.authentication;

import java.util.function.Function;

import reactor.core.publisher.Mono;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;

/**
 * An implementation of an
 * {@link org.springframework.security.authentication.AuthenticationProvider} for OAuth
 * 2.0 Login, which leverages the OAuth 2.0 Authorization Code Grant Flow.
 *
 * This {@link org.springframework.security.authentication.AuthenticationProvider} is
 * responsible for authenticating an Authorization Code credential with the Authorization
 * Server's Token Endpoint and if valid, exchanging it for an Access Token credential.
 * <p>
 * It will also obtain the user attributes of the End-User (Resource Owner) from the
 * UserInfo Endpoint using an
 * {@link org.springframework.security.oauth2.client.userinfo.OAuth2UserService}, which
 * will create a {@code Principal} in the form of an {@link OAuth2User}. The
 * {@code OAuth2User} is then associated to the {@link OAuth2LoginAuthenticationToken} to
 * complete the authentication.
 *
 * @author Rob Winch
 * @since 5.1
 * @see OAuth2LoginAuthenticationToken
 * @see ReactiveOAuth2AccessTokenResponseClient
 * @see ReactiveOAuth2UserService
 * @see OAuth2User
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section
 * 4.1 Authorization Code Grant Flow</a>
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc6749#section-4.1.3">Section 4.1.3 Access Token
 * Request</a>
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc6749#section-4.1.4">Section 4.1.4 Access Token
 * Response</a>
 */
public class OAuth2AuthorizationCodeReactiveAuthenticationManager implements ReactiveAuthenticationManager {

	private static final String INVALID_STATE_PARAMETER_ERROR_CODE = "invalid_state_parameter";

	private final ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;

	public OAuth2AuthorizationCodeReactiveAuthenticationManager(
			ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient) {
		Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
		this.accessTokenResponseClient = accessTokenResponseClient;
	}

	@Override
	public Mono<Authentication> authenticate(Authentication authentication) {
		return Mono.defer(() -> {
			OAuth2AuthorizationCodeAuthenticationToken token = (OAuth2AuthorizationCodeAuthenticationToken) authentication;
			OAuth2AuthorizationResponse authorizationResponse = token.getAuthorizationExchange()
					.getAuthorizationResponse();
			if (authorizationResponse.statusError()) {
				return Mono.error(new OAuth2AuthorizationException(authorizationResponse.getError()));
			}
			OAuth2AuthorizationRequest authorizationRequest = token.getAuthorizationExchange()
					.getAuthorizationRequest();
			if (!authorizationResponse.getState().equals(authorizationRequest.getState())) {
				OAuth2Error oauth2Error = new OAuth2Error(INVALID_STATE_PARAMETER_ERROR_CODE);
				return Mono.error(new OAuth2AuthorizationException(oauth2Error));
			}
			OAuth2AuthorizationCodeGrantRequest authzRequest = new OAuth2AuthorizationCodeGrantRequest(
					token.getClientRegistration(), token.getAuthorizationExchange());
			return this.accessTokenResponseClient.getTokenResponse(authzRequest).map(onSuccess(token));
		});
	}

	private Function<OAuth2AccessTokenResponse, OAuth2AuthorizationCodeAuthenticationToken> onSuccess(
			OAuth2AuthorizationCodeAuthenticationToken token) {
		return (accessTokenResponse) -> {
			ClientRegistration registration = token.getClientRegistration();
			OAuth2AuthorizationExchange exchange = token.getAuthorizationExchange();
			OAuth2AccessToken accessToken = accessTokenResponse.getAccessToken();
			OAuth2RefreshToken refreshToken = accessTokenResponse.getRefreshToken();
			return new OAuth2AuthorizationCodeAuthenticationToken(registration, exchange, accessToken, refreshToken,
					accessTokenResponse.getAdditionalParameters());
		};
	}

}
