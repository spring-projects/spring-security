/*
 * Copyright 2002-2022 the original author or authors.
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

import java.util.Arrays;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.util.Assert;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * The default implementation of an {@link OAuth2AccessTokenResponseClient} for the
 * {@link AuthorizationGrantType#CLIENT_CREDENTIALS client_credentials} grant. This
 * implementation uses a {@link RestOperations} when requesting an access token credential
 * at the Authorization Server's Token Endpoint.
 *
 * @author Joe Grandja
 * @since 5.1
 * @see OAuth2AccessTokenResponseClient
 * @see OAuth2ClientCredentialsGrantRequest
 * @see OAuth2AccessTokenResponse
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc6749#section-4.4.2">Section 4.4.2 Access Token Request
 * (Client Credentials Grant)</a>
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc6749#section-4.4.3">Section 4.4.3 Access Token Response
 * (Client Credentials Grant)</a>
 */
public final class DefaultClientCredentialsTokenResponseClient
		implements OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> {

	private static final String INVALID_TOKEN_RESPONSE_ERROR_CODE = "invalid_token_response";

	private Converter<OAuth2ClientCredentialsGrantRequest, RequestEntity<?>> requestEntityConverter = new OAuth2ClientCredentialsGrantRequestEntityConverter();

	private RestOperations restOperations;

	public DefaultClientCredentialsTokenResponseClient() {
		RestTemplate restTemplate = new RestTemplate(
				Arrays.asList(new FormHttpMessageConverter(), new OAuth2AccessTokenResponseHttpMessageConverter()));
		restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
		this.restOperations = restTemplate;
	}

	@Override
	public OAuth2AccessTokenResponse getTokenResponse(
			OAuth2ClientCredentialsGrantRequest clientCredentialsGrantRequest) {
		Assert.notNull(clientCredentialsGrantRequest, "clientCredentialsGrantRequest cannot be null");
		RequestEntity<?> request = this.requestEntityConverter.convert(clientCredentialsGrantRequest);
		ResponseEntity<OAuth2AccessTokenResponse> response = getResponse(request);
		// As per spec, in Section 5.1 Successful Access Token Response
		// https://tools.ietf.org/html/rfc6749#section-5.1
		// If AccessTokenResponse.scope is empty, then we assume all requested scopes were
		// granted.
		// However, we use the explicit scopes returned in the response (if any).
		return response.getBody();
	}

	private ResponseEntity<OAuth2AccessTokenResponse> getResponse(RequestEntity<?> request) {
		try {
			return this.restOperations.exchange(request, OAuth2AccessTokenResponse.class);
		}
		catch (RestClientException ex) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_TOKEN_RESPONSE_ERROR_CODE,
					"An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response: "
							+ ex.getMessage(),
					null);
			throw new OAuth2AuthorizationException(oauth2Error, ex);
		}
	}

	/**
	 * Sets the {@link Converter} used for converting the
	 * {@link OAuth2ClientCredentialsGrantRequest} to a {@link RequestEntity}
	 * representation of the OAuth 2.0 Access Token Request.
	 * @param requestEntityConverter the {@link Converter} used for converting to a
	 * {@link RequestEntity} representation of the Access Token Request
	 */
	public void setRequestEntityConverter(
			Converter<OAuth2ClientCredentialsGrantRequest, RequestEntity<?>> requestEntityConverter) {
		Assert.notNull(requestEntityConverter, "requestEntityConverter cannot be null");
		this.requestEntityConverter = requestEntityConverter;
	}

	/**
	 * Sets the {@link RestOperations} used when requesting the OAuth 2.0 Access Token
	 * Response.
	 *
	 * <p>
	 * <b>NOTE:</b> At a minimum, the supplied {@code restOperations} must be configured
	 * with the following:
	 * <ol>
	 * <li>{@link HttpMessageConverter}'s - {@link FormHttpMessageConverter} and
	 * {@link OAuth2AccessTokenResponseHttpMessageConverter}</li>
	 * <li>{@link ResponseErrorHandler} - {@link OAuth2ErrorResponseErrorHandler}</li>
	 * </ol>
	 * @param restOperations the {@link RestOperations} used when requesting the Access
	 * Token Response
	 */
	public void setRestOperations(RestOperations restOperations) {
		Assert.notNull(restOperations, "restOperations cannot be null");
		this.restOperations = restOperations;
	}

}
