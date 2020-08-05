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

import java.util.Collections;
import java.util.Set;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.web.reactive.function.BodyInserters;

/**
 * An implementation of a {@link ReactiveOAuth2AccessTokenResponseClient} that
 * &quot;exchanges&quot; an authorization code credential for an access token credential
 * at the Authorization Server's Token Endpoint.
 *
 * <p>
 * <b>NOTE:</b> This implementation uses the Nimbus OAuth 2.0 SDK internally.
 *
 * @author Rob Winch
 * @since 5.1
 * @see ReactiveOAuth2AccessTokenResponseClient
 * @see OAuth2AuthorizationCodeGrantRequest
 * @see OAuth2AccessTokenResponse
 * @see <a target="_blank" href=
 * "https://connect2id.com/products/nimbus-oauth-openid-connect-sdk">Nimbus OAuth 2.0
 * SDK</a>
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc6749#section-4.1.3">Section 4.1.3 Access Token Request
 * (Authorization Code Grant)</a>
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc6749#section-4.1.4">Section 4.1.4 Access Token Response
 * (Authorization Code Grant)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7636#section-4.2">Section
 * 4.2 Client Creates the Code Challenge</a>
 */
public class WebClientReactiveAuthorizationCodeTokenResponseClient
		extends AbstractWebClientReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {

	@Override
	ClientRegistration clientRegistration(OAuth2AuthorizationCodeGrantRequest grantRequest) {
		return grantRequest.getClientRegistration();
	}

	@Override
	Set<String> scopes(OAuth2AuthorizationCodeGrantRequest grantRequest) {
		return Collections.emptySet();
	}

	@Override
	Set<String> defaultScopes(OAuth2AuthorizationCodeGrantRequest grantRequest) {
		return grantRequest.getAuthorizationExchange().getAuthorizationRequest().getScopes();
	}

	@Override
	BodyInserters.FormInserter<String> populateTokenRequestBody(OAuth2AuthorizationCodeGrantRequest grantRequest,
			BodyInserters.FormInserter<String> body) {
		super.populateTokenRequestBody(grantRequest, body);
		OAuth2AuthorizationExchange authorizationExchange = grantRequest.getAuthorizationExchange();
		OAuth2AuthorizationResponse authorizationResponse = authorizationExchange.getAuthorizationResponse();
		body.with(OAuth2ParameterNames.CODE, authorizationResponse.getCode());
		String redirectUri = authorizationExchange.getAuthorizationRequest().getRedirectUri();
		if (redirectUri != null) {
			body.with(OAuth2ParameterNames.REDIRECT_URI, redirectUri);
		}
		String codeVerifier = authorizationExchange.getAuthorizationRequest()
				.getAttribute(PkceParameterNames.CODE_VERIFIER);
		if (codeVerifier != null) {
			body.with(PkceParameterNames.CODE_VERIFIER, codeVerifier);
		}
		return body;
	}

}
