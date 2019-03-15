/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.oauth2.core.web.reactive.function;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import net.minidev.json.JSONObject;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.ReactiveHttpInputMessage;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.web.reactive.function.BodyExtractor;
import org.springframework.web.reactive.function.BodyExtractors;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Provides a way to create an {@link OAuth2AccessTokenResponse} from a {@link ReactiveHttpInputMessage}
 * @author Rob Winch
 * @since 5.1
 */
class OAuth2AccessTokenResponseBodyExtractor
		implements BodyExtractor<Mono<OAuth2AccessTokenResponse>, ReactiveHttpInputMessage> {

	private static final String INVALID_TOKEN_RESPONSE_ERROR_CODE = "invalid_token_response";

	OAuth2AccessTokenResponseBodyExtractor() {}

	@Override
	public Mono<OAuth2AccessTokenResponse> extract(ReactiveHttpInputMessage inputMessage,
			Context context) {
		ParameterizedTypeReference<Map<String, String>> type = new ParameterizedTypeReference<Map<String, String>>() {};
		BodyExtractor<Mono<Map<String, String>>, ReactiveHttpInputMessage> delegate = BodyExtractors.toMono(type);
		return delegate.extract(inputMessage, context)
				.map(json -> parse(json))
				.flatMap(OAuth2AccessTokenResponseBodyExtractor::oauth2AccessTokenResponse)
				.map(OAuth2AccessTokenResponseBodyExtractor::oauth2AccessTokenResponse);
	}

	private static TokenResponse parse(Map<String, String> json) {
		try {
			return TokenResponse.parse(new JSONObject(json));
		}
		catch (ParseException pe) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_TOKEN_RESPONSE_ERROR_CODE,
					"An error occurred parsing the Access Token response: " + pe.getMessage(), null);
			throw new OAuth2AuthorizationException(oauth2Error, pe);
		}
	}

	private static Mono<AccessTokenResponse> oauth2AccessTokenResponse(TokenResponse tokenResponse) {
		if (tokenResponse.indicatesSuccess()) {
			return Mono.just(tokenResponse)
					.cast(AccessTokenResponse.class);
		}
		TokenErrorResponse tokenErrorResponse = (TokenErrorResponse) tokenResponse;
		ErrorObject errorObject = tokenErrorResponse.getErrorObject();
		OAuth2Error oauth2Error;
		if (errorObject == null) {
			oauth2Error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR);
		} else {
			oauth2Error = new OAuth2Error(
					errorObject.getCode() != null ? errorObject.getCode() : OAuth2ErrorCodes.SERVER_ERROR,
					errorObject.getDescription(),
					errorObject.getURI() != null ? errorObject.getURI().toString() : null);
		}
		return Mono.error(new OAuth2AuthorizationException(oauth2Error));
	}

	private static OAuth2AccessTokenResponse oauth2AccessTokenResponse(AccessTokenResponse accessTokenResponse) {
		AccessToken accessToken = accessTokenResponse.getTokens().getAccessToken();
		OAuth2AccessToken.TokenType accessTokenType = null;
		if (OAuth2AccessToken.TokenType.BEARER.getValue()
				.equalsIgnoreCase(accessToken.getType().getValue())) {
			accessTokenType = OAuth2AccessToken.TokenType.BEARER;
		}
		long expiresIn = accessToken.getLifetime();

		Set<String> scopes = accessToken.getScope() == null ?
				Collections.emptySet() : new LinkedHashSet<>(accessToken.getScope().toStringList());

		String refreshToken = null;
		if (accessTokenResponse.getTokens().getRefreshToken() != null) {
			refreshToken = accessTokenResponse.getTokens().getRefreshToken().getValue();
		}

		Map<String, Object> additionalParameters = new LinkedHashMap<>(accessTokenResponse.getCustomParameters());

		return OAuth2AccessTokenResponse.withToken(accessToken.getValue())
				.tokenType(accessTokenType)
				.expiresIn(expiresIn)
				.scopes(scopes)
				.refreshToken(refreshToken)
				.additionalParameters(additionalParameters)
				.build();
	}
}
