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

import java.net.URI;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Base implementation of a {@link Converter} that converts the provided
 * {@link AbstractOAuth2AuthorizationGrantRequest} instance to a {@link RequestEntity}
 * representation of an OAuth 2.0 Access Token Request for the Authorization Grant.
 *
 * @param <T> the type of {@link AbstractOAuth2AuthorizationGrantRequest}
 * @author Joe Grandja
 * @since 5.5
 * @see Converter
 * @see AbstractOAuth2AuthorizationGrantRequest
 * @see RequestEntity
 */
public abstract class AbstractOAuth2AuthorizationGrantRequestEntityConverter<T extends AbstractOAuth2AuthorizationGrantRequest>
		implements Converter<T, RequestEntity<?>> {

	// @formatter:off
	protected Converter<T, HttpHeaders> headersConverter =
			(authorizationGrantRequest) -> OAuth2AuthorizationGrantRequestEntityUtils
					.getTokenRequestHeaders(authorizationGrantRequest.getClientRegistration());
	// @formatter:on

	protected Converter<T, MultiValueMap<String, String>> parametersConverter = this::createParameters;

	/**
	 * Sub-class constructor.
	 */
	protected AbstractOAuth2AuthorizationGrantRequestEntityConverter() {
	}

	@Override
	public RequestEntity<?> convert(T authorizationGrantRequest) {
		HttpHeaders headers = this.headersConverter.convert(authorizationGrantRequest);
		MultiValueMap<String, String> parameters = this.parametersConverter.convert(authorizationGrantRequest);
		URI uri = UriComponentsBuilder
				.fromUriString(authorizationGrantRequest.getClientRegistration().getProviderDetails().getTokenUri())
				.build().toUri();
		return new RequestEntity<>(parameters, headers, HttpMethod.POST, uri);
	}

	/**
	 * Returns a {@link MultiValueMap} of the parameters used in the OAuth 2.0 Access
	 * Token Request body.
	 * @param authorizationGrantRequest the authorization grant request
	 * @return a {@link MultiValueMap} of the parameters used in the OAuth 2.0 Access
	 * Token Request body
	 */
	protected abstract MultiValueMap<String, String> createParameters(T authorizationGrantRequest);

	/**
	 * Sets the {@link Converter} used for converting the
	 * {@link AbstractOAuth2AuthorizationGrantRequest} instance to a {@link HttpHeaders}
	 * used in the OAuth 2.0 Access Token Request headers.
	 * @param headersConverter the {@link Converter} used for converting the
	 * {@link OAuth2AuthorizationCodeGrantRequest} to {@link HttpHeaders}
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
	 * {@link OAuth2AuthorizationCodeGrantRequest} to a {@link HttpHeaders}
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
	 * Sets the {@link Converter} used for converting the
	 * {@link AbstractOAuth2AuthorizationGrantRequest} instance to a {@link MultiValueMap}
	 * of the parameters used in the OAuth 2.0 Access Token Request body.
	 * @param parametersConverter the {@link Converter} used for converting the
	 * {@link OAuth2AuthorizationCodeGrantRequest} to a {@link MultiValueMap} of the
	 * parameters
	 */
	public final void setParametersConverter(Converter<T, MultiValueMap<String, String>> parametersConverter) {
		Assert.notNull(parametersConverter, "parametersConverter cannot be null");
		this.parametersConverter = parametersConverter;
	}

	/**
	 * Add (compose) the provided {@code parametersConverter} to the current
	 * {@link Converter} used for converting the
	 * {@link AbstractOAuth2AuthorizationGrantRequest} instance to a {@link MultiValueMap}
	 * of the parameters used in the OAuth 2.0 Access Token Request body.
	 * @param parametersConverter the {@link Converter} to add (compose) to the current
	 * {@link Converter} used for converting the
	 * {@link OAuth2AuthorizationCodeGrantRequest} to a {@link MultiValueMap} of the
	 * parameters
	 */
	public final void addParametersConverter(Converter<T, MultiValueMap<String, String>> parametersConverter) {
		Assert.notNull(parametersConverter, "parametersConverter cannot be null");
		Converter<T, MultiValueMap<String, String>> currentParametersConverter = this.parametersConverter;
		this.parametersConverter = (authorizationGrantRequest) -> {
			// Append parameters using a Composite Converter
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

}
