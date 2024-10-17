/*
 * Copyright 2002-2024 the original author or authors.
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

import java.util.function.Consumer;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClient.RequestHeadersSpec;
import org.springframework.web.client.RestClientException;

/**
 * Abstract base class for {@link RestClient}-based implementations of
 * {@link OAuth2AccessTokenResponseClient} that communicate to the Authorization Server's
 * Token Endpoint.
 * <p>
 * Submits a form request body specific to the type of grant request and accepts a JSON
 * response body containing an OAuth 2.0 Access Token Response or OAuth 2.0 Error
 * Response.
 *
 * @param <T> type of grant request
 * @author Steve Riesenberg
 * @since 6.4
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-3.2">RFC-6749 Token
 * Endpoint</a>
 * @see RestClientAuthorizationCodeTokenResponseClient
 * @see RestClientClientCredentialsTokenResponseClient
 * @see RestClientRefreshTokenTokenResponseClient
 * @see RestClientJwtBearerTokenResponseClient
 * @see RestClientTokenExchangeTokenResponseClient
 * @see DefaultOAuth2TokenRequestHeadersConverter
 */
public abstract class AbstractRestClientOAuth2AccessTokenResponseClient<T extends AbstractOAuth2AuthorizationGrantRequest>
		implements OAuth2AccessTokenResponseClient<T> {

	private static final String INVALID_TOKEN_RESPONSE_ERROR_CODE = "invalid_token_response";

	// @formatter:off
	private RestClient restClient = RestClient.builder()
			.messageConverters((messageConverters) -> {
				messageConverters.clear();
				messageConverters.add(new FormHttpMessageConverter());
				messageConverters.add(new OAuth2AccessTokenResponseHttpMessageConverter());
			})
			.defaultStatusHandler(new OAuth2ErrorResponseErrorHandler())
			.build();
	// @formatter:on

	private Converter<T, RequestHeadersSpec<?>> requestEntityConverter = this::validatingPopulateRequest;

	private Converter<T, HttpHeaders> headersConverter = new DefaultOAuth2TokenRequestHeadersConverter<>();

	private Converter<T, MultiValueMap<String, String>> parametersConverter = new DefaultOAuth2TokenRequestParametersConverter<>();

	private Consumer<MultiValueMap<String, String>> parametersCustomizer = (parameters) -> {
	};

	AbstractRestClientOAuth2AccessTokenResponseClient() {
	}

	@Override
	public OAuth2AccessTokenResponse getTokenResponse(T grantRequest) {
		Assert.notNull(grantRequest, "grantRequest cannot be null");
		try {
			// @formatter:off
			OAuth2AccessTokenResponse accessTokenResponse = this.requestEntityConverter.convert(grantRequest)
					.retrieve()
					.body(OAuth2AccessTokenResponse.class);
			// @formatter:on
			if (accessTokenResponse == null) {
				OAuth2Error error = new OAuth2Error(INVALID_TOKEN_RESPONSE_ERROR_CODE,
						"Empty OAuth 2.0 Access Token Response", null);
				throw new OAuth2AuthorizationException(error);
			}
			return accessTokenResponse;
		}
		catch (RestClientException ex) {
			OAuth2Error error = new OAuth2Error(INVALID_TOKEN_RESPONSE_ERROR_CODE,
					"An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response: "
							+ ex.getMessage(),
					null);
			throw new OAuth2AuthorizationException(error, ex);
		}
	}

	private RequestHeadersSpec<?> validatingPopulateRequest(T grantRequest) {
		validateClientAuthenticationMethod(grantRequest);
		return populateRequest(grantRequest);
	}

	private void validateClientAuthenticationMethod(T grantRequest) {
		ClientRegistration clientRegistration = grantRequest.getClientRegistration();
		ClientAuthenticationMethod clientAuthenticationMethod = clientRegistration.getClientAuthenticationMethod();
		boolean supportedClientAuthenticationMethod = clientAuthenticationMethod.equals(ClientAuthenticationMethod.NONE)
				|| clientAuthenticationMethod.equals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				|| clientAuthenticationMethod.equals(ClientAuthenticationMethod.CLIENT_SECRET_POST);
		if (!supportedClientAuthenticationMethod) {
			throw new IllegalArgumentException(String.format(
					"This class supports `client_secret_basic`, `client_secret_post`, and `none` by default. Client [%s] is using [%s] instead. Please use a supported client authentication method, or use `set/addParametersConverter` or `set/addHeadersConverter` to supply an instance that supports [%s].",
					clientRegistration.getRegistrationId(), clientAuthenticationMethod, clientAuthenticationMethod));
		}
	}

	private RequestHeadersSpec<?> populateRequest(T grantRequest) {
		MultiValueMap<String, String> parameters = this.parametersConverter.convert(grantRequest);
		if (parameters == null) {
			parameters = new LinkedMultiValueMap<>();
		}
		this.parametersCustomizer.accept(parameters);

		return this.restClient.post()
			.uri(grantRequest.getClientRegistration().getProviderDetails().getTokenUri())
			.headers((headers) -> {
				HttpHeaders headersToAdd = this.headersConverter.convert(grantRequest);
				if (headersToAdd != null) {
					headers.addAll(headersToAdd);
				}
			})
			.body(parameters);
	}

	/**
	 * Sets the {@link RestClient} used when requesting the OAuth 2.0 Access Token
	 * Response.
	 * @param restClient the {@link RestClient} used when requesting the Access Token
	 * Response
	 */
	public final void setRestClient(RestClient restClient) {
		Assert.notNull(restClient, "restClient cannot be null");
		this.restClient = restClient;
	}

	/**
	 * Sets the {@link Converter} used for converting the
	 * {@link AbstractOAuth2AuthorizationGrantRequest} instance to a {@link HttpHeaders}
	 * used in the OAuth 2.0 Access Token Request headers.
	 * @param headersConverter the {@link Converter} used for converting the
	 * {@link AbstractOAuth2AuthorizationGrantRequest} to {@link HttpHeaders}
	 */
	public final void setHeadersConverter(Converter<T, HttpHeaders> headersConverter) {
		Assert.notNull(headersConverter, "headersConverter cannot be null");
		this.headersConverter = headersConverter;
		this.requestEntityConverter = this::populateRequest;
	}

	/**
	 * Add (compose) the provided {@code headersConverter} to the current
	 * {@link Converter} used for converting the
	 * {@link AbstractOAuth2AuthorizationGrantRequest} instance to a {@link HttpHeaders}
	 * used in the OAuth 2.0 Access Token Request headers.
	 * @param headersConverter the {@link Converter} to add (compose) to the current
	 * {@link Converter} used for converting the
	 * {@link AbstractOAuth2AuthorizationGrantRequest} to a {@link HttpHeaders}
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
		this.requestEntityConverter = this::populateRequest;
	}

	/**
	 * Sets the {@link Converter} used for converting the
	 * {@link AbstractOAuth2AuthorizationGrantRequest} instance to a {@link MultiValueMap}
	 * used in the OAuth 2.0 Access Token Request body.
	 * @param parametersConverter the {@link Converter} used for converting the
	 * {@link AbstractOAuth2AuthorizationGrantRequest} to {@link MultiValueMap}
	 */
	public final void setParametersConverter(Converter<T, MultiValueMap<String, String>> parametersConverter) {
		Assert.notNull(parametersConverter, "parametersConverter cannot be null");
		if (parametersConverter instanceof DefaultOAuth2TokenRequestParametersConverter) {
			this.parametersConverter = parametersConverter;
		}
		else {
			Converter<T, MultiValueMap<String, String>> defaultParametersConverter = new DefaultOAuth2TokenRequestParametersConverter<>();
			this.parametersConverter = (authorizationGrantRequest) -> {
				MultiValueMap<String, String> parameters = defaultParametersConverter
					.convert(authorizationGrantRequest);
				MultiValueMap<String, String> parametersToSet = parametersConverter.convert(authorizationGrantRequest);
				if (parametersToSet != null) {
					parameters.putAll(parametersToSet);
				}
				return parameters;
			};
		}
		this.requestEntityConverter = this::populateRequest;
	}

	/**
	 * Add (compose) the provided {@code parametersConverter} to the current
	 * {@link Converter} used for converting the
	 * {@link AbstractOAuth2AuthorizationGrantRequest} instance to a {@link MultiValueMap}
	 * used in the OAuth 2.0 Access Token Request body.
	 * @param parametersConverter the {@link Converter} to add (compose) to the current
	 * {@link Converter} used for converting the
	 * {@link AbstractOAuth2AuthorizationGrantRequest} to a {@link MultiValueMap}
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
		this.requestEntityConverter = this::populateRequest;
	}

	/**
	 * Sets the {@link Consumer} used for customizing the OAuth 2.0 Access Token
	 * parameters, which allows for parameters to be added, overwritten or removed.
	 * @param parametersCustomizer the {@link Consumer} to customize the parameters
	 */
	public void setParametersCustomizer(Consumer<MultiValueMap<String, String>> parametersCustomizer) {
		Assert.notNull(parametersCustomizer, "parametersCustomizer cannot be null");
		this.parametersCustomizer = parametersCustomizer;
	}

}
