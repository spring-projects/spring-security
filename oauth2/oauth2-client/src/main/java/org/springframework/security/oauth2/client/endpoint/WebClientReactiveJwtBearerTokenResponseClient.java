/*
 * Copyright 2002-2021 the original author or authors.
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
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * The default implementation of an {@link ReactiveOAuth2AccessTokenResponseClient} for
 * the {@link AuthorizationGrantType#JWT_BEARER jwt-bearer} grant. This implementation
 * uses {@link WebClient} when requesting an access token credential at the Authorization
 * Server's Token Endpoint.
 *
 * @author Steve Riesenberg
 * @since 5.6
 * @see ReactiveOAuth2AccessTokenResponseClient
 * @see JwtBearerGrantRequest
 * @see OAuth2AccessToken
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7523#section-2.1">Section
 * 2.1 Using JWTs as Authorization Grants</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7521#section-4.1">Section
 * 4.1 Using Assertions as Authorization Grants</a>
 */
public final class WebClientReactiveJwtBearerTokenResponseClient
		extends AbstractWebClientReactiveOAuth2AccessTokenResponseClient<JwtBearerGrantRequest> {

	@Override
	ClientRegistration clientRegistration(JwtBearerGrantRequest grantRequest) {
		return grantRequest.getClientRegistration();
	}

	@Override
	Set<String> scopes(JwtBearerGrantRequest grantRequest) {
		return grantRequest.getClientRegistration().getScopes();
	}

	@Override
	BodyInserters.FormInserter<String> populateTokenRequestBody(JwtBearerGrantRequest grantRequest,
			BodyInserters.FormInserter<String> body) {
		return super.populateTokenRequestBody(grantRequest, body).with(OAuth2ParameterNames.ASSERTION,
				grantRequest.getJwt().getTokenValue());
	}

}
