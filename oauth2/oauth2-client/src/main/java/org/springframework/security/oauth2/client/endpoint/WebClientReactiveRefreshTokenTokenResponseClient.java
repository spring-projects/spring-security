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

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.function.Consumer;

import reactor.core.publisher.Mono;

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

import static org.springframework.security.oauth2.core.web.reactive.function.OAuth2BodyExtractors.oauth2AccessTokenResponse;

/**
 * An implementation of a {@link ReactiveOAuth2AccessTokenResponseClient}
 * for the {@link AuthorizationGrantType#REFRESH_TOKEN refresh_token} grant.
 * This implementation uses {@link WebClient} when requesting
 * an access token credential at the Authorization Server's Token Endpoint.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see ReactiveOAuth2AccessTokenResponseClient
 * @see OAuth2RefreshTokenGrantRequest
 * @see OAuth2AccessTokenResponse
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-6">Section 6 Refreshing an Access Token</a>
 */
public final class WebClientReactiveRefreshTokenTokenResponseClient implements ReactiveOAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> {
	private static final String INVALID_TOKEN_RESPONSE_ERROR_CODE = "invalid_token_response";
	private WebClient webClient = WebClient.builder().build();

	@Override
	public Mono<OAuth2AccessTokenResponse> getTokenResponse(OAuth2RefreshTokenGrantRequest refreshTokenGrantRequest) {
		Assert.notNull(refreshTokenGrantRequest, "refreshTokenGrantRequest cannot be null");
		return Mono.defer(() -> {
			ClientRegistration clientRegistration = refreshTokenGrantRequest.getClientRegistration();
			return this.webClient.post()
					.uri(clientRegistration.getProviderDetails().getTokenUri())
					.headers(tokenRequestHeaders(clientRegistration))
					.body(tokenRequestBody(refreshTokenGrantRequest))
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
					.map(tokenResponse -> tokenResponse(refreshTokenGrantRequest, tokenResponse));
		});
	}

	private static Consumer<HttpHeaders> tokenRequestHeaders(ClientRegistration clientRegistration) {
		return headers -> {
			headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
			headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
			if (ClientAuthenticationMethod.BASIC.equals(clientRegistration.getClientAuthenticationMethod())) {
				String clientId = encodeClientCredential(clientRegistration.getClientId());
				String clientSecret = encodeClientCredential(clientRegistration.getClientSecret());
				headers.setBasicAuth(clientId, clientSecret);
			}
		};
	}

	private static String encodeClientCredential(String clientCredential) {
		try {
			return URLEncoder.encode(clientCredential, StandardCharsets.UTF_8.toString());
		}
		catch (UnsupportedEncodingException ex) {
			// Will not happen since UTF-8 is a standard charset
			throw new IllegalArgumentException(ex);
		}
	}

	private static BodyInserters.FormInserter<String> tokenRequestBody(OAuth2RefreshTokenGrantRequest refreshTokenGrantRequest) {
		ClientRegistration clientRegistration = refreshTokenGrantRequest.getClientRegistration();
		BodyInserters.FormInserter<String> body = BodyInserters.fromFormData(
				OAuth2ParameterNames.GRANT_TYPE, refreshTokenGrantRequest.getGrantType().getValue());
		body.with(OAuth2ParameterNames.REFRESH_TOKEN,
				refreshTokenGrantRequest.getRefreshToken().getTokenValue());
		if (!CollectionUtils.isEmpty(refreshTokenGrantRequest.getScopes())) {
			body.with(OAuth2ParameterNames.SCOPE,
					StringUtils.collectionToDelimitedString(refreshTokenGrantRequest.getScopes(), " "));
		}
		if (ClientAuthenticationMethod.POST.equals(clientRegistration.getClientAuthenticationMethod())) {
			body.with(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
			body.with(OAuth2ParameterNames.CLIENT_SECRET, clientRegistration.getClientSecret());
		}
		return body;
	}

	private static OAuth2AccessTokenResponse tokenResponse(OAuth2RefreshTokenGrantRequest refreshTokenGrantRequest,
															OAuth2AccessTokenResponse accessTokenResponse) {
		if (!CollectionUtils.isEmpty(accessTokenResponse.getAccessToken().getScopes()) &&
				accessTokenResponse.getRefreshToken() != null) {
			return accessTokenResponse;
		}

		OAuth2AccessTokenResponse.Builder tokenResponseBuilder = OAuth2AccessTokenResponse.withResponse(accessTokenResponse);
		if (CollectionUtils.isEmpty(accessTokenResponse.getAccessToken().getScopes())) {
			// As per spec, in Section 5.1 Successful Access Token Response
			// https://tools.ietf.org/html/rfc6749#section-5.1
			// If AccessTokenResponse.scope is empty, then default to the scope
			// originally requested by the client in the Token Request
			tokenResponseBuilder.scopes(refreshTokenGrantRequest.getAccessToken().getScopes());
		}
		if (accessTokenResponse.getRefreshToken() == null) {
			// Reuse existing refresh token
			tokenResponseBuilder.refreshToken(refreshTokenGrantRequest.getRefreshToken().getTokenValue());
		}
		return tokenResponseBuilder.build();
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
