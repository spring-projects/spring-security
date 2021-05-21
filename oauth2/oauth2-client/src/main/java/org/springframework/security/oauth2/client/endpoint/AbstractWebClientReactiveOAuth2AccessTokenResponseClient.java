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

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Set;

import reactor.core.publisher.Mono;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.oauth2.core.web.reactive.function.OAuth2BodyExtractors.oauth2AccessTokenResponse;

/**
 * Abstract base class for all of the {@code WebClientReactive*TokenResponseClient}s
 * that communicate to the Authorization Server's Token Endpoint.
 *
 * <p>Submits a form request body specific to the type of grant request.</p>
 *
 * <p>Accepts a JSON response body containing an OAuth 2.0 Access token or error.</p>
 *
 * @author Phil Clay
 * @since 5.3
 * @param <T> type of grant request
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-3.2">RFC-6749 Token Endpoint</a>
 * @see WebClientReactiveAuthorizationCodeTokenResponseClient
 * @see WebClientReactiveClientCredentialsTokenResponseClient
 * @see WebClientReactivePasswordTokenResponseClient
 * @see WebClientReactiveRefreshTokenTokenResponseClient
 */
abstract class AbstractWebClientReactiveOAuth2AccessTokenResponseClient<T extends AbstractOAuth2AuthorizationGrantRequest>
		implements ReactiveOAuth2AccessTokenResponseClient<T> {

	private WebClient webClient = WebClient.builder().build();

	@Override
	public Mono<OAuth2AccessTokenResponse> getTokenResponse(T grantRequest) {
		Assert.notNull(grantRequest, "grantRequest cannot be null");
		return Mono.defer(() -> this.webClient.post()
				.uri(clientRegistration(grantRequest).getProviderDetails().getTokenUri())
				.headers(headers -> populateTokenRequestHeaders(grantRequest, headers))
				.body(createTokenRequestBody(grantRequest))
				.exchange()
				.flatMap(response -> readTokenResponse(grantRequest, response)));
	}

	/**
	 * Returns the {@link ClientRegistration} for the given {@code grantRequest}.
	 *
	 * @param grantRequest the grant request
	 * @return the {@link ClientRegistration} for the given {@code grantRequest}.
	 */
	abstract ClientRegistration clientRegistration(T grantRequest);

	/**
	 * Populates the headers for the token request.
	 *
	 * @param grantRequest the grant request
	 * @param headers the headers to populate
	 */
	private void populateTokenRequestHeaders(T grantRequest, HttpHeaders headers) {
		ClientRegistration clientRegistration = clientRegistration(grantRequest);
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
		if (ClientAuthenticationMethod.BASIC.equals(clientRegistration.getClientAuthenticationMethod())) {
			String clientId = encodeClientCredential(clientRegistration.getClientId());
			String clientSecret = encodeClientCredential(clientRegistration.getClientSecret());
			headers.setBasicAuth(clientId, clientSecret);
		}
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

	/**
	 * Creates and returns the body for the token request.
	 *
	 * <p>This method pre-populates the body with some standard properties,
	 * and then delegates to {@link #populateTokenRequestBody(AbstractOAuth2AuthorizationGrantRequest, BodyInserters.FormInserter)}
	 * for subclasses to further populate the body before returning.</p>
	 *
	 * @param grantRequest the grant request
	 * @return the body for the token request.
	 */
	private BodyInserters.FormInserter<String> createTokenRequestBody(T grantRequest) {
		BodyInserters.FormInserter<String> body = BodyInserters
				.fromFormData(OAuth2ParameterNames.GRANT_TYPE, grantRequest.getGrantType().getValue());
		return populateTokenRequestBody(grantRequest, body);
	}

	/**
	 * Populates the body of the token request.
	 *
	 * <p>By default, populates properties that are common to all grant types.
	 * Subclasses can extend this method to populate grant type specific properties.</p>
	 *
	 * @param grantRequest the grant request
	 * @param body the body to populate
	 * @return the populated body
	 */
	BodyInserters.FormInserter<String> populateTokenRequestBody(T grantRequest, BodyInserters.FormInserter<String> body) {
		ClientRegistration clientRegistration = clientRegistration(grantRequest);
		if (!ClientAuthenticationMethod.BASIC.equals(clientRegistration.getClientAuthenticationMethod())) {
			body.with(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
		}
		if (ClientAuthenticationMethod.POST.equals(clientRegistration.getClientAuthenticationMethod())) {
			body.with(OAuth2ParameterNames.CLIENT_SECRET, clientRegistration.getClientSecret());
		}
		Set<String> scopes = scopes(grantRequest);
		if (!CollectionUtils.isEmpty(scopes)) {
			body.with(OAuth2ParameterNames.SCOPE,
					StringUtils.collectionToDelimitedString(scopes, " "));
		}
		return body;
	}

	/**
	 * Returns the scopes to include as a property in the token request.
	 *
	 * @param grantRequest the grant request
	 * @return the scopes to include as a property in the token request.
	 */
	abstract Set<String> scopes(T grantRequest);

	/**
	 * Returns the scopes to include in the response if the authorization
	 * server returned no scopes in the response.
	 *
	 * <p>As per <a href="https://tools.ietf.org/html/rfc6749#section-5.1">RFC-6749 Section 5.1 Successful Access Token Response</a>,
	 * if AccessTokenResponse.scope is empty, then default to the scope
	 * originally requested by the client in the Token Request.</p>
	 *
	 * @param grantRequest the grant request
	 * @return the scopes to include in the response if the authorization
	 *         server returned no scopes.
	 */
	Set<String> defaultScopes(T grantRequest) {
		return scopes(grantRequest);
	}

	/**
	 * Reads the token response from the response body.
	 *
	 * @param grantRequest the request for which the response was received.
	 * @param response the client response from which to read
	 * @return the token response from the response body.
	 */
	private Mono<OAuth2AccessTokenResponse> readTokenResponse(T grantRequest, ClientResponse response) {
		return response.body(oauth2AccessTokenResponse())
				.map(tokenResponse -> populateTokenResponse(grantRequest, tokenResponse));
	}

	/**
	 * Populates the given {@link OAuth2AccessTokenResponse} with additional details
	 * from the grant request.
	 *
	 * @param grantRequest the request for which the response was received.
	 * @param tokenResponse the original token response
	 * @return a token response optionally populated with additional details from the request.
	 */
	OAuth2AccessTokenResponse populateTokenResponse(T grantRequest, OAuth2AccessTokenResponse tokenResponse) {
		if (CollectionUtils.isEmpty(tokenResponse.getAccessToken().getScopes())) {
			Set<String> defaultScopes = defaultScopes(grantRequest);
			tokenResponse = OAuth2AccessTokenResponse.withResponse(tokenResponse)
					.scopes(defaultScopes)
					.build();
		}
		return tokenResponse;
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
