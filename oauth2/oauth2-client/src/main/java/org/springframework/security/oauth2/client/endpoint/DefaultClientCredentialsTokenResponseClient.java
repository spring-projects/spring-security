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

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * The default implementation of an {@link OAuth2AccessTokenResponseClient}
 * for the {@link AuthorizationGrantType#CLIENT_CREDENTIALS client_credentials} grant.
 * This implementation uses a {@link RestOperations} when requesting
 * an access token credential at the Authorization Server's Token Endpoint.
 *
 * @author Joe Grandja
 * @since 5.1
 * @see OAuth2AccessTokenResponseClient
 * @see OAuth2ClientCredentialsGrantRequest
 * @see OAuth2AccessTokenResponse
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.4.2">Section 4.4.2 Access Token Request (Client Credentials Grant)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.4.3">Section 4.4.3 Access Token Response (Client Credentials Grant)</a>
 */
public class DefaultClientCredentialsTokenResponseClient implements OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> {
	private static final String INVALID_TOKEN_REQUEST_ERROR_CODE = "invalid_token_request";

	private static final String INVALID_TOKEN_RESPONSE_ERROR_CODE = "invalid_token_response";

	private static final String[] TOKEN_RESPONSE_PARAMETER_NAMES = {
			OAuth2ParameterNames.ACCESS_TOKEN,
			OAuth2ParameterNames.TOKEN_TYPE,
			OAuth2ParameterNames.EXPIRES_IN,
			OAuth2ParameterNames.SCOPE,
			OAuth2ParameterNames.REFRESH_TOKEN
	};

	private RestOperations restOperations;

	public DefaultClientCredentialsTokenResponseClient() {
		RestTemplate restTemplate = new RestTemplate();
		// Disable the ResponseErrorHandler as errors are handled directly within this class
		restTemplate.setErrorHandler(new NoOpResponseErrorHandler());
		this.restOperations = restTemplate;
	}

	@Override
	public OAuth2AccessTokenResponse getTokenResponse(OAuth2ClientCredentialsGrantRequest clientCredentialsGrantRequest)
			throws OAuth2AuthenticationException {

		Assert.notNull(clientCredentialsGrantRequest, "clientCredentialsGrantRequest cannot be null");

		ClientRegistration clientRegistration = clientCredentialsGrantRequest.getClientRegistration();

		// Headers
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		if (ClientAuthenticationMethod.BASIC.equals(clientRegistration.getClientAuthenticationMethod())) {
			headers.setBasicAuth(clientRegistration.getClientId(), clientRegistration.getClientSecret());
		}

		// Form parameters
		MultiValueMap<String, String> formParameters = new LinkedMultiValueMap<>();
		formParameters.add(OAuth2ParameterNames.GRANT_TYPE, clientCredentialsGrantRequest.getGrantType().getValue());
		if (!CollectionUtils.isEmpty(clientRegistration.getScopes())) {
			formParameters.add(OAuth2ParameterNames.SCOPE,
					StringUtils.collectionToDelimitedString(clientRegistration.getScopes(), " "));
		}
		if (ClientAuthenticationMethod.POST.equals(clientRegistration.getClientAuthenticationMethod())) {
			formParameters.add(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
			formParameters.add(OAuth2ParameterNames.CLIENT_SECRET, clientRegistration.getClientSecret());
		}

		// Request
		URI uri = UriComponentsBuilder.fromUriString(clientRegistration.getProviderDetails().getTokenUri())
				.build()
				.toUri();
		RequestEntity<MultiValueMap<String, String>> request =
				new RequestEntity<>(formParameters, headers, HttpMethod.POST, uri);

		ParameterizedTypeReference<Map<String, String>> typeReference =
				new ParameterizedTypeReference<Map<String, String>>() {};

		// Exchange
		ResponseEntity<Map<String, String>> response;
		try {
			response = this.restOperations.exchange(request, typeReference);
		} catch (Exception ex) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_TOKEN_REQUEST_ERROR_CODE,
					"An error occurred while sending the Access Token Request: " + ex.getMessage(), null);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), ex);
		}

		Map<String, String> responseParameters = response.getBody();

		// Check for Error Response
		if (response.getStatusCodeValue() != 200) {
			OAuth2Error oauth2Error = this.parseErrorResponse(responseParameters);
			if (oauth2Error == null) {
				oauth2Error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR);
			}
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}

		// Success Response
		OAuth2AccessTokenResponse tokenResponse;
		try {
			tokenResponse = this.parseTokenResponse(responseParameters);
		} catch (Exception ex) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_TOKEN_RESPONSE_ERROR_CODE,
				"An error occurred parsing the Access Token response (200 OK): " + ex.getMessage(), null);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), ex);
		}

		if (tokenResponse == null) {
			// This should never happen as long as the provider
			// implements a Successful Response as defined in Section 5.1
			// https://tools.ietf.org/html/rfc6749#section-5.1
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_TOKEN_RESPONSE_ERROR_CODE,
					"An error occurred parsing the Access Token response (200 OK). " +
							"Missing required parameters: access_token and/or token_type", null);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}

		if (CollectionUtils.isEmpty(tokenResponse.getAccessToken().getScopes())) {
			// As per spec, in Section 5.1 Successful Access Token Response
			// https://tools.ietf.org/html/rfc6749#section-5.1
			// If AccessTokenResponse.scope is empty, then default to the scope
			// originally requested by the client in the Token Request
			tokenResponse = OAuth2AccessTokenResponse.withResponse(tokenResponse)
					.scopes(clientRegistration.getScopes())
					.build();
		}

		return tokenResponse;
	}

	/**
	 * Sets the {@link RestOperations} used when requesting the access token response.
	 *
	 * @param restOperations the {@link RestOperations} used when requesting the access token response
	 */
	public final void setRestOperations(RestOperations restOperations) {
		Assert.notNull(restOperations, "restOperations cannot be null");
		this.restOperations = restOperations;
	}

	private OAuth2Error parseErrorResponse(Map<String, String> responseParameters) {
		if (CollectionUtils.isEmpty(responseParameters) ||
				!responseParameters.containsKey(OAuth2ParameterNames.ERROR)) {
			return null;
		}

		String errorCode = responseParameters.get(OAuth2ParameterNames.ERROR);
		String errorDescription = responseParameters.get(OAuth2ParameterNames.ERROR_DESCRIPTION);
		String errorUri = responseParameters.get(OAuth2ParameterNames.ERROR_URI);

		return new OAuth2Error(errorCode, errorDescription, errorUri);
	}

	private OAuth2AccessTokenResponse parseTokenResponse(Map<String, String> responseParameters) {
		if (CollectionUtils.isEmpty(responseParameters) ||
				!responseParameters.containsKey(OAuth2ParameterNames.ACCESS_TOKEN) ||
				!responseParameters.containsKey(OAuth2ParameterNames.TOKEN_TYPE)) {
			return null;
		}

		String accessToken = responseParameters.get(OAuth2ParameterNames.ACCESS_TOKEN);

		OAuth2AccessToken.TokenType accessTokenType = null;
		if (OAuth2AccessToken.TokenType.BEARER.getValue().equalsIgnoreCase(
				responseParameters.get(OAuth2ParameterNames.TOKEN_TYPE))) {
			accessTokenType = OAuth2AccessToken.TokenType.BEARER;
		}

		long expiresIn = 0;
		if (responseParameters.containsKey(OAuth2ParameterNames.EXPIRES_IN)) {
			try {
				expiresIn = Long.valueOf(responseParameters.get(OAuth2ParameterNames.EXPIRES_IN));
			} catch (NumberFormatException ex) { }
		}

		Set<String> scopes = Collections.emptySet();
		if (responseParameters.containsKey(OAuth2ParameterNames.SCOPE)) {
			String scope = responseParameters.get(OAuth2ParameterNames.SCOPE);
			scopes = Arrays.stream(StringUtils.delimitedListToStringArray(scope, " ")).collect(Collectors.toSet());
		}

		Map<String, Object> additionalParameters = new LinkedHashMap<>();
		Set<String> tokenResponseParameterNames = Stream.of(TOKEN_RESPONSE_PARAMETER_NAMES).collect(Collectors.toSet());
		responseParameters.entrySet().stream()
				.filter(e -> !tokenResponseParameterNames.contains(e.getKey()))
				.forEach(e -> additionalParameters.put(e.getKey(), e.getValue()));

		return OAuth2AccessTokenResponse.withToken(accessToken)
				.tokenType(accessTokenType)
				.expiresIn(expiresIn)
				.scopes(scopes)
				.additionalParameters(additionalParameters)
				.build();
	}

	private static class NoOpResponseErrorHandler implements ResponseErrorHandler {

		@Override
		public boolean hasError(ClientHttpResponse response) throws IOException {
			return false;
		}

		@Override
		public void handleError(ClientHttpResponse response) throws IOException {
		}
	}
}
