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

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.mockito.InOrder;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationExchanges;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationRequests;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationResponses;
import org.springframework.util.MultiValueMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link OAuth2AuthorizationCodeGrantRequestEntityConverter}.
 *
 * @author Joe Grandja
 */
public class OAuth2AuthorizationCodeGrantRequestEntityConverterTests {

	private OAuth2AuthorizationCodeGrantRequestEntityConverter converter;

	@Before
	public void setup() {
		this.converter = new OAuth2AuthorizationCodeGrantRequestEntityConverter();
	}

	@Test
	public void setHeadersConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.converter.setHeadersConverter(null))
				.withMessage("headersConverter cannot be null");
	}

	@Test
	public void addHeadersConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.converter.addHeadersConverter(null))
				.withMessage("headersConverter cannot be null");
	}

	@Test
	public void setParametersConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.converter.setParametersConverter(null))
				.withMessage("parametersConverter cannot be null");
	}

	@Test
	public void addParametersConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.converter.addParametersConverter(null))
				.withMessage("parametersConverter cannot be null");
	}

	@Test
	public void convertWhenHeadersConverterSetThenCalled() {
		Converter<OAuth2AuthorizationCodeGrantRequest, HttpHeaders> headersConverter1 = mock(Converter.class);
		this.converter.setHeadersConverter(headersConverter1);
		Converter<OAuth2AuthorizationCodeGrantRequest, HttpHeaders> headersConverter2 = mock(Converter.class);
		this.converter.addHeadersConverter(headersConverter2);
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		OAuth2AuthorizationExchange authorizationExchange = TestOAuth2AuthorizationExchanges.success();
		OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest = new OAuth2AuthorizationCodeGrantRequest(
				clientRegistration, authorizationExchange);
		this.converter.convert(authorizationCodeGrantRequest);
		InOrder inOrder = inOrder(headersConverter1, headersConverter2);
		inOrder.verify(headersConverter1).convert(any(OAuth2AuthorizationCodeGrantRequest.class));
		inOrder.verify(headersConverter2).convert(any(OAuth2AuthorizationCodeGrantRequest.class));
	}

	@Test
	public void convertWhenParametersConverterSetThenCalled() {
		Converter<OAuth2AuthorizationCodeGrantRequest, MultiValueMap<String, String>> parametersConverter1 = mock(
				Converter.class);
		this.converter.setParametersConverter(parametersConverter1);
		Converter<OAuth2AuthorizationCodeGrantRequest, MultiValueMap<String, String>> parametersConverter2 = mock(
				Converter.class);
		this.converter.addParametersConverter(parametersConverter2);
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		OAuth2AuthorizationExchange authorizationExchange = TestOAuth2AuthorizationExchanges.success();
		OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest = new OAuth2AuthorizationCodeGrantRequest(
				clientRegistration, authorizationExchange);
		this.converter.convert(authorizationCodeGrantRequest);
		InOrder inOrder = inOrder(parametersConverter1, parametersConverter2);
		inOrder.verify(parametersConverter1).convert(any(OAuth2AuthorizationCodeGrantRequest.class));
		inOrder.verify(parametersConverter2).convert(any(OAuth2AuthorizationCodeGrantRequest.class));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void convertWhenGrantRequestValidThenConverts() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		OAuth2AuthorizationExchange authorizationExchange = TestOAuth2AuthorizationExchanges.success();
		OAuth2AuthorizationRequest authorizationRequest = authorizationExchange.getAuthorizationRequest();
		OAuth2AuthorizationResponse authorizationResponse = authorizationExchange.getAuthorizationResponse();
		OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest = new OAuth2AuthorizationCodeGrantRequest(
				clientRegistration, authorizationExchange);
		RequestEntity<?> requestEntity = this.converter.convert(authorizationCodeGrantRequest);
		assertThat(requestEntity.getMethod()).isEqualTo(HttpMethod.POST);
		assertThat(requestEntity.getUrl().toASCIIString())
				.isEqualTo(clientRegistration.getProviderDetails().getTokenUri());
		HttpHeaders headers = requestEntity.getHeaders();
		assertThat(headers.getAccept()).contains(MediaType.APPLICATION_JSON);
		assertThat(headers.getContentType())
				.isEqualTo(MediaType.valueOf(MediaType.APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8"));
		assertThat(headers.getFirst(HttpHeaders.AUTHORIZATION)).startsWith("Basic ");
		MultiValueMap<String, String> formParameters = (MultiValueMap<String, String>) requestEntity.getBody();
		assertThat(formParameters.getFirst(OAuth2ParameterNames.GRANT_TYPE))
				.isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.CODE)).isEqualTo(authorizationResponse.getCode());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.CLIENT_ID)).isNull();
		assertThat(formParameters.getFirst(OAuth2ParameterNames.REDIRECT_URI))
				.isEqualTo(authorizationRequest.getRedirectUri());
	}

	@SuppressWarnings("unchecked")
	@Test
	public void convertWhenPkceGrantRequestValidThenConverts() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration()
				.clientAuthenticationMethod(null).clientSecret(null).build();
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(PkceParameterNames.CODE_VERIFIER, "code-verifier-1234");
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE, "code-challenge-1234");
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
		OAuth2AuthorizationRequest authorizationRequest = TestOAuth2AuthorizationRequests.request()
				.attributes(attributes).additionalParameters(additionalParameters).build();
		OAuth2AuthorizationResponse authorizationResponse = TestOAuth2AuthorizationResponses.success().build();
		OAuth2AuthorizationExchange authorizationExchange = new OAuth2AuthorizationExchange(authorizationRequest,
				authorizationResponse);
		OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest = new OAuth2AuthorizationCodeGrantRequest(
				clientRegistration, authorizationExchange);
		RequestEntity<?> requestEntity = this.converter.convert(authorizationCodeGrantRequest);
		assertThat(requestEntity.getMethod()).isEqualTo(HttpMethod.POST);
		assertThat(requestEntity.getUrl().toASCIIString())
				.isEqualTo(clientRegistration.getProviderDetails().getTokenUri());
		HttpHeaders headers = requestEntity.getHeaders();
		assertThat(headers.getAccept()).contains(MediaType.APPLICATION_JSON);
		assertThat(headers.getContentType())
				.isEqualTo(MediaType.valueOf(MediaType.APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8"));
		assertThat(headers.getFirst(HttpHeaders.AUTHORIZATION)).isNull();
		MultiValueMap<String, String> formParameters = (MultiValueMap<String, String>) requestEntity.getBody();
		assertThat(formParameters.getFirst(OAuth2ParameterNames.GRANT_TYPE))
				.isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.CODE)).isEqualTo(authorizationResponse.getCode());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.REDIRECT_URI))
				.isEqualTo(authorizationRequest.getRedirectUri());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.CLIENT_ID))
				.isEqualTo(authorizationRequest.getClientId());
		assertThat(formParameters.getFirst(PkceParameterNames.CODE_VERIFIER))
				.isEqualTo(authorizationRequest.getAttribute(PkceParameterNames.CODE_VERIFIER));
	}

}
