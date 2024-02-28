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

import java.util.Set;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * The default implementation of an {@link ReactiveOAuth2AccessTokenResponseClient} for
 * the {@link AuthorizationGrantType#TOKEN_EXCHANGE token-exchange} grant. This
 * implementation uses {@link WebClient} when requesting an access token credential at the
 * Authorization Server's Token Endpoint.
 *
 * @author Steve Riesenberg
 * @since 6.3
 * @see ReactiveOAuth2AccessTokenResponseClient
 * @see TokenExchangeGrantRequest
 * @see OAuth2AccessToken
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc8693#section-2.1">Section
 * 2.1 Request</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc8693#section-2.2">Section
 * 2.2 Response</a>
 */
public final class WebClientReactiveTokenExchangeTokenResponseClient
		extends AbstractWebClientReactiveOAuth2AccessTokenResponseClient<TokenExchangeGrantRequest> {

	private static final String ACCESS_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:access_token";

	private static final String JWT_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:jwt";

	@Override
	ClientRegistration clientRegistration(TokenExchangeGrantRequest grantRequest) {
		return grantRequest.getClientRegistration();
	}

	@Override
	Set<String> scopes(TokenExchangeGrantRequest grantRequest) {
		return grantRequest.getClientRegistration().getScopes();
	}

	@Override
	BodyInserters.FormInserter<String> populateTokenRequestBody(TokenExchangeGrantRequest grantRequest,
			BodyInserters.FormInserter<String> body) {
		super.populateTokenRequestBody(grantRequest, body);
		body.with(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE, ACCESS_TOKEN_TYPE_VALUE);
		OAuth2Token subjectToken = grantRequest.getSubjectToken();
		body.with(OAuth2ParameterNames.SUBJECT_TOKEN, subjectToken.getTokenValue());
		body.with(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, tokenType(subjectToken));
		OAuth2Token actorToken = grantRequest.getActorToken();
		if (actorToken != null) {
			body.with(OAuth2ParameterNames.ACTOR_TOKEN, actorToken.getTokenValue());
			body.with(OAuth2ParameterNames.ACTOR_TOKEN_TYPE, tokenType(actorToken));
		}
		return body;
	}

	private static String tokenType(OAuth2Token token) {
		return (token instanceof Jwt) ? JWT_TOKEN_TYPE_VALUE : ACCESS_TOKEN_TYPE_VALUE;
	}

}
