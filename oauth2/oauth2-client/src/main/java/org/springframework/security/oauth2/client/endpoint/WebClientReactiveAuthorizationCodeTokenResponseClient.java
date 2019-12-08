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
package org.springframework.security.oauth2.client.endpoint;

import org.springframework.http.MediaType;
import org.springframework.http.ReactiveHttpInputMessage;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.web.reactive.function.BodyExtractor;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.util.Assert;
import reactor.core.publisher.Mono;

import static org.springframework.security.oauth2.core.web.reactive.function.OAuth2BodyExtractors.oauth2AccessTokenResponse;

/**
 * An implementation of an {@link ReactiveOAuth2AccessTokenResponseClient} that &quot;exchanges&quot;
 * an authorization code credential for an access token credential
 * at the Authorization Server's Token Endpoint.
 *
 * <p>
 * <b>NOTE:</b> This implementation uses the Nimbus OAuth 2.0 SDK internally.
 *
 * @author Rob Winch
 * @since 5.1
 * @see OAuth2AccessTokenResponseClient
 * @see OAuth2AuthorizationCodeGrantRequest
 * @see OAuth2AccessTokenResponse
 * @see <a target="_blank" href="https://connect2id.com/products/nimbus-oauth-openid-connect-sdk">Nimbus OAuth 2.0 SDK</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.3">Section 4.1.3 Access Token Request (Authorization Code Grant)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.4">Section 4.1.4 Access Token Response (Authorization Code Grant)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7636#section-4.2">Section 4.2 Client Creates the Code Challenge</a>
 */
public class WebClientReactiveAuthorizationCodeTokenResponseClient implements ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {
	private WebClient webClient = WebClient.builder()
			.build();
	private BodyExtractor<Mono<OAuth2AccessTokenResponse>, ReactiveHttpInputMessage> tokenResponseBodyExtractor = oauth2AccessTokenResponse();

	/**
	 * @param webClient the webClient to set
	 */
	public void setWebClient(WebClient webClient) {
		Assert.notNull(webClient, "webClient cannot be null");
		this.webClient = webClient;
	}

	/**
	 * Sets the extractor that will be used to read {@link OAuth2AccessTokenResponse} from token response body.
	 *
	 * @param tokenResponseBodyExtractor body extractor (cannot be {@code null})
	 */
	public void setTokenResponseBodyExtractor(BodyExtractor<Mono<OAuth2AccessTokenResponse>, ReactiveHttpInputMessage> tokenResponseBodyExtractor) {
		Assert.notNull(tokenResponseBodyExtractor, "tokenResponseBodyExtractor cannot be null");
		this.tokenResponseBodyExtractor = tokenResponseBodyExtractor;
	}

	@Override
	public Mono<OAuth2AccessTokenResponse> getTokenResponse(OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest) {
		return Mono.defer(() -> {
			ClientRegistration clientRegistration = authorizationGrantRequest.getClientRegistration();
			OAuth2AuthorizationExchange authorizationExchange = authorizationGrantRequest.getAuthorizationExchange();
			String tokenUri = clientRegistration.getProviderDetails().getTokenUri();
			BodyInserters.FormInserter<String> body = body(authorizationExchange, clientRegistration);

			return this.webClient.post()
					.uri(tokenUri)
					.accept(MediaType.APPLICATION_JSON)
					.headers(headers -> {
						if (ClientAuthenticationMethod.BASIC.equals(clientRegistration.getClientAuthenticationMethod())) {
							headers.setBasicAuth(clientRegistration.getClientId(), clientRegistration.getClientSecret());
						}
					})
					.body(body)
					.exchange()
					.flatMap(response -> response.body(tokenResponseBodyExtractor))
					.map(response -> {
						if (response.getAccessToken().getScopes().isEmpty()) {
							response = OAuth2AccessTokenResponse.withResponse(response)
								.scopes(authorizationExchange.getAuthorizationRequest().getScopes())
								.build();
						}
						return response;
					});
		});
	}

	private static BodyInserters.FormInserter<String> body(OAuth2AuthorizationExchange authorizationExchange, ClientRegistration clientRegistration) {
		OAuth2AuthorizationResponse authorizationResponse = authorizationExchange.getAuthorizationResponse();
		BodyInserters.FormInserter<String> body = BodyInserters
				.fromFormData(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.with(OAuth2ParameterNames.CODE, authorizationResponse.getCode());
		String redirectUri = authorizationExchange.getAuthorizationRequest().getRedirectUri();
		String codeVerifier = authorizationExchange.getAuthorizationRequest().getAttribute(PkceParameterNames.CODE_VERIFIER);
		if (redirectUri != null) {
			body.with(OAuth2ParameterNames.REDIRECT_URI, redirectUri);
		}
		if (!ClientAuthenticationMethod.BASIC.equals(clientRegistration.getClientAuthenticationMethod())) {
			body.with(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
		}
		if (ClientAuthenticationMethod.POST.equals(clientRegistration.getClientAuthenticationMethod())) {
			body.with(OAuth2ParameterNames.CLIENT_SECRET, clientRegistration.getClientSecret());
		}
		if (codeVerifier != null) {
			body.with(PkceParameterNames.CODE_VERIFIER, codeVerifier);
		}
		return body;
	}
}
