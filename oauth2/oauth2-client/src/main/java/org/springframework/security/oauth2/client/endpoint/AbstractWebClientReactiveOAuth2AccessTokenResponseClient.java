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

import reactor.core.publisher.Mono;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ReactiveHttpInputMessage;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.web.reactive.function.OAuth2BodyExtractors;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyExtractor;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClient.RequestHeadersSpec;

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
 * @author Steve Riesenberg
 * @since 5.3
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-3.2">RFC-6749 Token
 * Endpoint</a>
 * @see WebClientReactiveAuthorizationCodeTokenResponseClient
 * @see WebClientReactiveClientCredentialsTokenResponseClient
 * @see WebClientReactivePasswordTokenResponseClient
 * @see WebClientReactiveRefreshTokenTokenResponseClient
 * @see DefaultOAuth2TokenRequestHeadersConverter
 */
public abstract class AbstractWebClientReactiveOAuth2AccessTokenResponseClient<T extends AbstractOAuth2AuthorizationGrantRequest>
		implements ReactiveOAuth2AccessTokenResponseClient<T> {

	private WebClient webClient = WebClient.builder().build();

	private Converter<T, RequestHeadersSpec<?>> requestEntityConverter = this::validatingPopulateRequest;

	private Converter<T, HttpHeaders> headersConverter = new DefaultOAuth2TokenRequestHeadersConverter<>();

	private Converter<T, MultiValueMap<String, String>> parametersConverter = new DefaultOAuth2TokenRequestParametersConverter<>();

	private Consumer<MultiValueMap<String, String>> parametersCustomizer = (parameters) -> {
	};

	private BodyExtractor<Mono<OAuth2AccessTokenResponse>, ReactiveHttpInputMessage> bodyExtractor = OAuth2BodyExtractors
		.oauth2AccessTokenResponse();

	AbstractWebClientReactiveOAuth2AccessTokenResponseClient() {
	}

	@Override
	public Mono<OAuth2AccessTokenResponse> getTokenResponse(T grantRequest) {
		Assert.notNull(grantRequest, "grantRequest cannot be null");
		// @formatter:off
		return Mono.defer(() -> this.requestEntityConverter.convert(grantRequest)
				.exchange()
				.flatMap((response) -> response.body(this.bodyExtractor))
		);
		// @formatter:on
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

		return this.webClient.post()
			.uri(grantRequest.getClientRegistration().getProviderDetails().getTokenUri())
			.headers((headers) -> {
				HttpHeaders headersToAdd = this.headersConverter.convert(grantRequest);
				if (headersToAdd != null) {
					headers.addAll(headersToAdd);
				}
			})
			.body(BodyInserters.fromFormData(parameters));
	}

	/**
	 * Sets the {@link WebClient} used when requesting the OAuth 2.0 Access Token
	 * Response.
	 * @param webClient the {@link WebClient} used when requesting the Access Token
	 * Response
	 */
	public final void setWebClient(WebClient webClient) {
		Assert.notNull(webClient, "webClient cannot be null");
		this.webClient = webClient;
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
		this.requestEntityConverter = this::populateRequest;
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
