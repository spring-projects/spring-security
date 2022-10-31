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

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Set;

import reactor.core.publisher.Mono;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ReactiveHttpInputMessage;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.web.reactive.function.OAuth2BodyExtractors;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.BodyExtractor;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Abstract base class for all of the {@code WebClientReactive*TokenResponseClient}s that
 * communicate to the Authorization Server's Token Endpoint.
 *
 * <p>
 * Submits a form request body specific to the type of grant request.
 * </p>
 *
 * <p>
 * Accepts a JSON response body containing an OAuth 2.0 Access token or error.
 * </p>
 *
 * @param <T> type of grant request
 * @author Phil Clay
 * @since 5.3
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-3.2">RFC-6749 Token
 * Endpoint</a>
 * @see WebClientReactiveAuthorizationCodeTokenResponseClient
 * @see WebClientReactiveClientCredentialsTokenResponseClient
 * @see WebClientReactivePasswordTokenResponseClient
 * @see WebClientReactiveRefreshTokenTokenResponseClient
 */
public abstract class AbstractWebClientReactiveOAuth2AccessTokenResponseClient<T extends AbstractOAuth2AuthorizationGrantRequest>
		implements ReactiveOAuth2AccessTokenResponseClient<T> {

	private WebClient webClient = WebClient.builder().build();

	private Converter<T, HttpHeaders> headersConverter = this::populateTokenRequestHeaders;

	private Converter<T, MultiValueMap<String, String>> parametersConverter = this::populateTokenRequestParameters;

	private BodyExtractor<Mono<OAuth2AccessTokenResponse>, ReactiveHttpInputMessage> bodyExtractor = OAuth2BodyExtractors
			.oauth2AccessTokenResponse();

	AbstractWebClientReactiveOAuth2AccessTokenResponseClient() {
	}

	@Override
	public Mono<OAuth2AccessTokenResponse> getTokenResponse(T grantRequest) {
		Assert.notNull(grantRequest, "grantRequest cannot be null");
		// @formatter:off
		return Mono.defer(() -> this.webClient.post()
				.uri(clientRegistration(grantRequest).getProviderDetails().getTokenUri())
				.headers((headers) -> {
					HttpHeaders headersToAdd = getHeadersConverter().convert(grantRequest);
					if (headersToAdd != null) {
						headers.addAll(headersToAdd);
					}
				})
				.body(createTokenRequestBody(grantRequest))
				.exchange()
				.flatMap((response) -> readTokenResponse(grantRequest, response))
		);
		// @formatter:on
	}

	/**
	 * Returns the {@link ClientRegistration} for the given {@code grantRequest}.
	 * @param grantRequest the grant request
	 * @return the {@link ClientRegistration} for the given {@code grantRequest}.
	 */
	abstract ClientRegistration clientRegistration(T grantRequest);

	/**
	 * Populates the headers for the token request.
	 * @param grantRequest the grant request
	 * @return the headers populated for the token request
	 */
	private HttpHeaders populateTokenRequestHeaders(T grantRequest) {
		HttpHeaders headers = new HttpHeaders();
		ClientRegistration clientRegistration = clientRegistration(grantRequest);
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
		if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(clientRegistration.getClientAuthenticationMethod())) {
			String clientId = encodeClientCredential(clientRegistration.getClientId());
			String clientSecret = encodeClientCredential(clientRegistration.getClientSecret());
			headers.setBasicAuth(clientId, clientSecret);
		}
		return headers;
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
	 * Populates default parameters for the token request.
	 * @param grantRequest the grant request
	 * @return the parameters populated for the token request.
	 */
	private MultiValueMap<String, String> populateTokenRequestParameters(T grantRequest) {
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.add(OAuth2ParameterNames.GRANT_TYPE, grantRequest.getGrantType().getValue());
		return parameters;
	}

	/**
	 * Combine the results of {@code parametersConverter} and
	 * {@link #populateTokenRequestBody}.
	 *
	 * <p>
	 * This method pre-populates the body with some standard properties, and then
	 * delegates to
	 * {@link #populateTokenRequestBody(AbstractOAuth2AuthorizationGrantRequest, BodyInserters.FormInserter)}
	 * for subclasses to further populate the body before returning.
	 * </p>
	 * @param grantRequest the grant request
	 * @return the body for the token request.
	 */
	private BodyInserters.FormInserter<String> createTokenRequestBody(T grantRequest) {
		MultiValueMap<String, String> parameters = getParametersConverter().convert(grantRequest);
		return populateTokenRequestBody(grantRequest, BodyInserters.fromFormData(parameters));
	}

	/**
	 * Populates the body of the token request.
	 *
	 * <p>
	 * By default, populates properties that are common to all grant types. Subclasses can
	 * extend this method to populate grant type specific properties.
	 * </p>
	 * @param grantRequest the grant request
	 * @param body the body to populate
	 * @return the populated body
	 */
	BodyInserters.FormInserter<String> populateTokenRequestBody(T grantRequest,
			BodyInserters.FormInserter<String> body) {
		ClientRegistration clientRegistration = clientRegistration(grantRequest);
		if (!ClientAuthenticationMethod.CLIENT_SECRET_BASIC
				.equals(clientRegistration.getClientAuthenticationMethod())) {
			body.with(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
		}
		if (ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(clientRegistration.getClientAuthenticationMethod())) {
			body.with(OAuth2ParameterNames.CLIENT_SECRET, clientRegistration.getClientSecret());
		}
		Set<String> scopes = scopes(grantRequest);
		if (!CollectionUtils.isEmpty(scopes)) {
			body.with(OAuth2ParameterNames.SCOPE, StringUtils.collectionToDelimitedString(scopes, " "));
		}
		return body;
	}

	/**
	 * Returns the scopes to include as a property in the token request.
	 * @param grantRequest the grant request
	 * @return the scopes to include as a property in the token request.
	 */
	abstract Set<String> scopes(T grantRequest);

	/**
	 * Returns the scopes to include in the response if the authorization server returned
	 * no scopes in the response.
	 *
	 * <p>
	 * As per <a href="https://tools.ietf.org/html/rfc6749#section-5.1">RFC-6749 Section
	 * 5.1 Successful Access Token Response</a>, if AccessTokenResponse.scope is empty,
	 * then default to the scope originally requested by the client in the Token Request.
	 * </p>
	 * @param grantRequest the grant request
	 * @return the scopes to include in the response if the authorization server returned
	 * no scopes.
	 */
	Set<String> defaultScopes(T grantRequest) {
		return Collections.emptySet();
	}

	/**
	 * Reads the token response from the response body.
	 * @param grantRequest the request for which the response was received.
	 * @param response the client response from which to read
	 * @return the token response from the response body.
	 */
	private Mono<OAuth2AccessTokenResponse> readTokenResponse(T grantRequest, ClientResponse response) {
		return response.body(this.bodyExtractor)
				.map((tokenResponse) -> populateTokenResponse(grantRequest, tokenResponse));
	}

	/**
	 * Populates the given {@link OAuth2AccessTokenResponse} with additional details from
	 * the grant request.
	 * @param grantRequest the request for which the response was received.
	 * @param tokenResponse the original token response
	 * @return a token response optionally populated with additional details from the
	 * request.
	 */
	OAuth2AccessTokenResponse populateTokenResponse(T grantRequest, OAuth2AccessTokenResponse tokenResponse) {
		if (CollectionUtils.isEmpty(tokenResponse.getAccessToken().getScopes())) {
			Set<String> defaultScopes = defaultScopes(grantRequest);
			// @formatter:off
			tokenResponse = OAuth2AccessTokenResponse
					.withResponse(tokenResponse)
					.scopes(defaultScopes)
					.build();
			// @formatter:on
		}
		return tokenResponse;
	}

	/**
	 * Sets the {@link WebClient} used when requesting the OAuth 2.0 Access Token
	 * Response.
	 * @param webClient the {@link WebClient} used when requesting the Access Token
	 * Response
	 */
	public void setWebClient(WebClient webClient) {
		Assert.notNull(webClient, "webClient cannot be null");
		this.webClient = webClient;
	}

	/**
	 * Returns the {@link Converter} used for converting the
	 * {@link AbstractOAuth2AuthorizationGrantRequest} instance to a {@link HttpHeaders}
	 * used in the OAuth 2.0 Access Token Request headers.
	 * @return the {@link Converter} used for converting the
	 * {@link AbstractOAuth2AuthorizationGrantRequest} to {@link HttpHeaders}
	 */
	final Converter<T, HttpHeaders> getHeadersConverter() {
		return this.headersConverter;
	}

	/**
	 * Sets the {@link Converter} used for converting the
	 * {@link AbstractOAuth2AuthorizationGrantRequest} instance to a {@link HttpHeaders}
	 * used in the OAuth 2.0 Access Token Request headers.
	 * @param headersConverter the {@link Converter} used for converting the
	 * {@link AbstractOAuth2AuthorizationGrantRequest} to {@link HttpHeaders}
	 * @since 5.6
	 */
	public final void setHeadersConverter(Converter<T, HttpHeaders> headersConverter) {
		Assert.notNull(headersConverter, "headersConverter cannot be null");
		this.headersConverter = headersConverter;
	}

	/**
	 * Add (compose) the provided {@code headersConverter} to the current
	 * {@link Converter} used for converting the
	 * {@link AbstractOAuth2AuthorizationGrantRequest} instance to a {@link HttpHeaders}
	 * used in the OAuth 2.0 Access Token Request headers.
	 * @param headersConverter the {@link Converter} to add (compose) to the current
	 * {@link Converter} used for converting the
	 * {@link AbstractOAuth2AuthorizationGrantRequest} to a {@link HttpHeaders}
	 * @since 5.6
	 */
	public final void addHeadersConverter(Converter<T, HttpHeaders> headersConverter) {
		Assert.notNull(headersConverter, "headersConverter cannot be null");
		Converter<T, HttpHeaders> currentHeadersConverter = this.headersConverter;
		this.headersConverter = (authorizationGrantRequest) -> {
			// Append headers using a Composite Converter
			HttpHeaders headers = currentHeadersConverter.convert(authorizationGrantRequest);
			if (headers == null) {
				headers = new HttpHeaders();
			}
			HttpHeaders headersToAdd = headersConverter.convert(authorizationGrantRequest);
			if (headersToAdd != null) {
				headers.addAll(headersToAdd);
			}
			return headers;
		};
	}

	/**
	 * Returns the {@link Converter} used for converting the
	 * {@link AbstractOAuth2AuthorizationGrantRequest} instance to a {@link MultiValueMap}
	 * used in the OAuth 2.0 Access Token Request body.
	 * @return the {@link Converter} used for converting the
	 * {@link AbstractOAuth2AuthorizationGrantRequest} to {@link MultiValueMap}
	 */
	final Converter<T, MultiValueMap<String, String>> getParametersConverter() {
		return this.parametersConverter;
	}

	/**
	 * Sets the {@link Converter} used for converting the
	 * {@link AbstractOAuth2AuthorizationGrantRequest} instance to a {@link MultiValueMap}
	 * used in the OAuth 2.0 Access Token Request body.
	 * @param parametersConverter the {@link Converter} used for converting the
	 * {@link AbstractOAuth2AuthorizationGrantRequest} to {@link MultiValueMap}
	 * @since 5.6
	 */
	public final void setParametersConverter(Converter<T, MultiValueMap<String, String>> parametersConverter) {
		Assert.notNull(parametersConverter, "parametersConverter cannot be null");
		this.parametersConverter = parametersConverter;
	}

	/**
	 * Add (compose) the provided {@code parametersConverter} to the current
	 * {@link Converter} used for converting the
	 * {@link AbstractOAuth2AuthorizationGrantRequest} instance to a {@link MultiValueMap}
	 * used in the OAuth 2.0 Access Token Request body.
	 * @param parametersConverter the {@link Converter} to add (compose) to the current
	 * {@link Converter} used for converting the
	 * {@link AbstractOAuth2AuthorizationGrantRequest} to a {@link MultiValueMap}
	 * @since 5.6
	 */
	public final void addParametersConverter(Converter<T, MultiValueMap<String, String>> parametersConverter) {
		Assert.notNull(parametersConverter, "parametersConverter cannot be null");
		Converter<T, MultiValueMap<String, String>> currentParametersConverter = this.parametersConverter;
		this.parametersConverter = (authorizationGrantRequest) -> {
			MultiValueMap<String, String> parameters = currentParametersConverter.convert(authorizationGrantRequest);
			if (parameters == null) {
				parameters = new LinkedMultiValueMap<>();
			}
			MultiValueMap<String, String> parametersToAdd = parametersConverter.convert(authorizationGrantRequest);
			if (parametersToAdd != null) {
				parameters.addAll(parametersToAdd);
			}
			return parameters;
		};
	}

	/**
	 * Sets the {@link BodyExtractor} that will be used to decode the
	 * {@link OAuth2AccessTokenResponse}
	 * @param bodyExtractor the {@link BodyExtractor} that will be used to decode the
	 * {@link OAuth2AccessTokenResponse}
	 * @since 5.6
	 */
	public final void setBodyExtractor(
			BodyExtractor<Mono<OAuth2AccessTokenResponse>, ReactiveHttpInputMessage> bodyExtractor) {
		Assert.notNull(bodyExtractor, "bodyExtractor cannot be null");
		this.bodyExtractor = bodyExtractor;
	}

}
