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

import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.function.Consumer;

import static org.springframework.security.oauth2.core.web.reactive.function.OAuth2BodyExtractors.oauth2AccessTokenResponse;

/**
 * An implementation of a {@link ReactiveOAuth2AccessTokenResponseClient}
 * for the {@link AuthorizationGrantType#PASSWORD password} grant.
 * This implementation uses {@link WebClient} when requesting
 * an access token credential at the Authorization Server's Token Endpoint.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see ReactiveOAuth2AccessTokenResponseClient
 * @see OAuth2PasswordGrantRequest
 * @see OAuth2AccessTokenResponse
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.3.2">Section 4.3.2 Access Token Request (Resource Owner Password Credentials Grant)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.3.3">Section 4.3.3 Access Token Response (Resource Owner Password Credentials Grant)</a>
 */
public final class WebClientReactivePasswordTokenResponseClient implements ReactiveOAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> {
	private static final String INVALID_TOKEN_RESPONSE_ERROR_CODE = "invalid_token_response";
	private WebClient webClient = WebClient.builder().build();

	@Override
	public Mono<OAuth2AccessTokenResponse> getTokenResponse(OAuth2PasswordGrantRequest passwordGrantRequest) {
		Assert.notNull(passwordGrantRequest, "passwordGrantRequest cannot be null");
		return Mono.defer(() -> {
			ClientRegistration clientRegistration = passwordGrantRequest.getClientRegistration();
			return this.webClient.post()
					.uri(clientRegistration.getProviderDetails().getTokenUri())
					.headers(tokenRequestHeaders(clientRegistration))
					.body(tokenRequestBody(passwordGrantRequest))
					.exchange()
					.flatMap(response -> {
						HttpStatus status = HttpStatus.resolve(response.rawStatusCode());
						if (status == null || !status.is2xxSuccessful()) {
							OAuth2Error oauth2Error = new OAuth2Error(INVALID_TOKEN_RESPONSE_ERROR_CODE,
									"An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response: " +
											"HTTP Status Code " + response.rawStatusCode(), null);
							return response
									.bodyToMono(DataBuffer.class)
									.map(DataBufferUtils::release)
									.then(Mono.error(new OAuth2AuthorizationException(oauth2Error)));
						}
						return response.body(oauth2AccessTokenResponse());
					})
					.map(tokenResponse -> {
						if (CollectionUtils.isEmpty(tokenResponse.getAccessToken().getScopes())) {
							// As per spec, in Section 5.1 Successful Access Token Response
							// https://tools.ietf.org/html/rfc6749#section-5.1
							// If AccessTokenResponse.scope is empty, then default to the scope
							// originally requested by the client in the Token Request
							tokenResponse = OAuth2AccessTokenResponse.withResponse(tokenResponse)
									.scopes(passwordGrantRequest.getClientRegistration().getScopes())
									.build();
						}
						return tokenResponse;
					});
		});
	}

	private static Consumer<HttpHeaders> tokenRequestHeaders(ClientRegistration clientRegistration) {
		return headers -> {
			headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
			headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
			if (ClientAuthenticationMethod.BASIC.equals(clientRegistration.getClientAuthenticationMethod())) {
				headers.setBasicAuth(clientRegistration.getClientId(), clientRegistration.getClientSecret());
			}
		};
	}

	private static BodyInserters.FormInserter<String> tokenRequestBody(OAuth2PasswordGrantRequest passwordGrantRequest) {
		ClientRegistration clientRegistration = passwordGrantRequest.getClientRegistration();
		BodyInserters.FormInserter<String> body = BodyInserters.fromFormData(
				OAuth2ParameterNames.GRANT_TYPE, passwordGrantRequest.getGrantType().getValue());
		body.with(OAuth2ParameterNames.USERNAME, passwordGrantRequest.getUsername());
		body.with(OAuth2ParameterNames.PASSWORD, passwordGrantRequest.getPassword());
		if (!CollectionUtils.isEmpty(passwordGrantRequest.getClientRegistration().getScopes())) {
			body.with(OAuth2ParameterNames.SCOPE,
					StringUtils.collectionToDelimitedString(passwordGrantRequest.getClientRegistration().getScopes(), " "));
		}
		if (ClientAuthenticationMethod.POST.equals(clientRegistration.getClientAuthenticationMethod())) {
			body.with(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
			body.with(OAuth2ParameterNames.CLIENT_SECRET, clientRegistration.getClientSecret());
		}
		return body;
	}

	/**
	 * Sets the {@link WebClient} used when requesting the OAuth 2.0 Access Token Response.
	 *
	 * @param webClient the {@link WebClient} used when requesting the Access Token Response
	 */
	public void setWebClient(WebClient webClient) {
		Assert.notNull(webClient, "webClient cannot be null");
		this.webClient = webClient;
	}
}
