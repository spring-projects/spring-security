/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.endpoint;

import static org.springframework.web.reactive.function.client.ExchangeFilterFunctions.Credentials.basicAuthenticationCredentials;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.util.CollectionUtils;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ExchangeFilterFunctions;
import org.springframework.web.reactive.function.client.WebClient;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;

import net.minidev.json.JSONObject;
import reactor.core.publisher.Mono;

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
 */
public class NimbusReactiveAuthorizationCodeTokenResponseClient implements ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {
	private static final String INVALID_TOKEN_RESPONSE_ERROR_CODE = "invalid_token_response";

	private WebClient webClient = WebClient.builder()
			.filter(ExchangeFilterFunctions.basicAuthentication())
			.build();

	@Override
	public Mono<OAuth2AccessTokenResponse> getTokenResponse(OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest)
			throws OAuth2AuthenticationException {

		return Mono.defer(() -> {
			ClientRegistration clientRegistration = authorizationGrantRequest.getClientRegistration();

			OAuth2AuthorizationExchange authorizationExchange = authorizationGrantRequest.getAuthorizationExchange();
			String tokenUri = clientRegistration.getProviderDetails().getTokenUri();
			BodyInserters.FormInserter<String> body = body(authorizationExchange);

			return this.webClient.post()
					.uri(tokenUri)
					.accept(MediaType.APPLICATION_JSON)
					.attributes(basicAuthenticationCredentials(clientRegistration.getClientId(), clientRegistration.getClientSecret()))
					.body(body)
					.retrieve()
					.onStatus(s -> false, response -> {
						throw new IllegalStateException("Disabled Status Handlers");
					})
					.bodyToMono(new ParameterizedTypeReference<Map<String, String>>() {})
					.map(json -> parse(json))
					.flatMap(tokenResponse -> accessTokenResponse(tokenResponse))
					.map(accessTokenResponse -> {
						AccessToken accessToken = accessTokenResponse.getTokens().getAccessToken();
						OAuth2AccessToken.TokenType accessTokenType = null;
						if (OAuth2AccessToken.TokenType.BEARER.getValue().equalsIgnoreCase(
								accessToken.getType().getValue())) {
							accessTokenType = OAuth2AccessToken.TokenType.BEARER;
						}
						long expiresIn = accessToken.getLifetime();

						// As per spec, in section 5.1 Successful Access Token Response
						// https://tools.ietf.org/html/rfc6749#section-5.1
						// If AccessTokenResponse.scope is empty, then default to the scope
						// originally requested by the client in the Authorization Request
						Set<String> scopes;
						if (CollectionUtils.isEmpty(
								accessToken.getScope())) {
							scopes = new LinkedHashSet<>(
									authorizationExchange.getAuthorizationRequest().getScopes());
						}
						else {
							scopes = new LinkedHashSet<>(
									accessToken.getScope().toStringList());
						}

						Map<String, Object> additionalParameters = new LinkedHashMap<>(
								accessTokenResponse.getCustomParameters());

						return OAuth2AccessTokenResponse.withToken(accessToken.getValue())
								.tokenType(accessTokenType)
								.expiresIn(expiresIn)
								.scopes(scopes)
								.additionalParameters(additionalParameters)
								.build();
					});
		});
	}

	private static BodyInserters.FormInserter<String> body(OAuth2AuthorizationExchange authorizationExchange) {
		OAuth2AuthorizationResponse authorizationResponse = authorizationExchange.getAuthorizationResponse();
		String redirectUri = authorizationExchange.getAuthorizationRequest().getRedirectUri();
		BodyInserters.FormInserter<String> body = BodyInserters
				.fromFormData("grant_type", AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.with("code", authorizationResponse.getCode());
		if (redirectUri != null) {
			body.with("redirect_uri", redirectUri);
		}
		return body;
	}

	private static Mono<AccessTokenResponse> accessTokenResponse(TokenResponse tokenResponse) {
		if (tokenResponse.indicatesSuccess()) {
			return Mono.just(tokenResponse)
					.cast(AccessTokenResponse.class);
		}
		TokenErrorResponse tokenErrorResponse = (TokenErrorResponse) tokenResponse;
		ErrorObject errorObject = tokenErrorResponse.getErrorObject();
		OAuth2Error oauth2Error = new OAuth2Error(errorObject.getCode(),
				errorObject.getDescription(), (errorObject.getURI() != null ?
				errorObject.getURI().toString() :
				null));

		return Mono.error(new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString()));
	}

	private static TokenResponse parse(Map<String, String> json) {
		try {
			return TokenResponse.parse(new JSONObject(json));
		}
		catch (ParseException pe) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_TOKEN_RESPONSE_ERROR_CODE,
					"An error occurred parsing the Access Token response: " + pe.getMessage(), null);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), pe);
		}
	}
}
