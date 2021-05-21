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
import java.util.Base64;

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
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.MultiValueMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link OAuth2ClientCredentialsGrantRequestEntityConverter}.
 *
 * @author Joe Grandja
 */
public class OAuth2ClientCredentialsGrantRequestEntityConverterTests {

	private OAuth2ClientCredentialsGrantRequestEntityConverter converter;

	@Before
	public void setup() {
		this.converter = new OAuth2ClientCredentialsGrantRequestEntityConverter();
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
		Converter<OAuth2ClientCredentialsGrantRequest, HttpHeaders> headersConverter1 = mock(Converter.class);
		this.converter.setHeadersConverter(headersConverter1);
		Converter<OAuth2ClientCredentialsGrantRequest, HttpHeaders> headersConverter2 = mock(Converter.class);
		this.converter.addHeadersConverter(headersConverter2);
		ClientRegistration clientRegistration = TestClientRegistrations.clientCredentials().build();
		OAuth2ClientCredentialsGrantRequest clientCredentialsGrantRequest = new OAuth2ClientCredentialsGrantRequest(
				clientRegistration);
		this.converter.convert(clientCredentialsGrantRequest);
		InOrder inOrder = inOrder(headersConverter1, headersConverter2);
		inOrder.verify(headersConverter1).convert(any(OAuth2ClientCredentialsGrantRequest.class));
		inOrder.verify(headersConverter2).convert(any(OAuth2ClientCredentialsGrantRequest.class));
	}

	@Test
	public void convertWhenParametersConverterSetThenCalled() {
		Converter<OAuth2ClientCredentialsGrantRequest, MultiValueMap<String, String>> parametersConverter1 = mock(
				Converter.class);
		this.converter.setParametersConverter(parametersConverter1);
		Converter<OAuth2ClientCredentialsGrantRequest, MultiValueMap<String, String>> parametersConverter2 = mock(
				Converter.class);
		this.converter.addParametersConverter(parametersConverter2);
		ClientRegistration clientRegistration = TestClientRegistrations.clientCredentials().build();
		OAuth2ClientCredentialsGrantRequest clientCredentialsGrantRequest = new OAuth2ClientCredentialsGrantRequest(
				clientRegistration);
		this.converter.convert(clientCredentialsGrantRequest);
		InOrder inOrder = inOrder(parametersConverter1, parametersConverter2);
		inOrder.verify(parametersConverter1).convert(any(OAuth2ClientCredentialsGrantRequest.class));
		inOrder.verify(parametersConverter2).convert(any(OAuth2ClientCredentialsGrantRequest.class));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void convertWhenGrantRequestValidThenConverts() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientCredentials().build();
		OAuth2ClientCredentialsGrantRequest clientCredentialsGrantRequest = new OAuth2ClientCredentialsGrantRequest(
				clientRegistration);
		RequestEntity<?> requestEntity = this.converter.convert(clientCredentialsGrantRequest);
		assertThat(requestEntity.getMethod()).isEqualTo(HttpMethod.POST);
		assertThat(requestEntity.getUrl().toASCIIString())
				.isEqualTo(clientRegistration.getProviderDetails().getTokenUri());
		HttpHeaders headers = requestEntity.getHeaders();
		assertThat(headers.getAccept()).contains(MediaType.APPLICATION_JSON_UTF8);
		assertThat(headers.getContentType())
				.isEqualTo(MediaType.valueOf(MediaType.APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8"));
		assertThat(headers.getFirst(HttpHeaders.AUTHORIZATION)).startsWith("Basic ");
		MultiValueMap<String, String> formParameters = (MultiValueMap<String, String>) requestEntity.getBody();
		assertThat(formParameters.getFirst(OAuth2ParameterNames.GRANT_TYPE))
				.isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.SCOPE)).contains(clientRegistration.getScopes());
	}

	// gh-9610
	@SuppressWarnings("unchecked")
	@Test
	public void convertWhenSpecialCharactersThenConvertsWithEncodedClientCredentials()
			throws UnsupportedEncodingException {
		String clientCredentialWithAnsiKeyboardSpecialCharacters = "~!@#$%^&*()_+{}|:\"<>?`-=[]\\;',./ ";
		// @formatter:off
		ClientRegistration clientRegistration = TestClientRegistrations.clientCredentials()
				.clientId(clientCredentialWithAnsiKeyboardSpecialCharacters)
				.clientSecret(clientCredentialWithAnsiKeyboardSpecialCharacters)
				.build();
		// @formatter:on
		OAuth2ClientCredentialsGrantRequest clientCredentialsGrantRequest = new OAuth2ClientCredentialsGrantRequest(
				clientRegistration);
		RequestEntity<?> requestEntity = this.converter.convert(clientCredentialsGrantRequest);
		assertThat(requestEntity.getMethod()).isEqualTo(HttpMethod.POST);
		assertThat(requestEntity.getUrl().toASCIIString())
				.isEqualTo(clientRegistration.getProviderDetails().getTokenUri());
		HttpHeaders headers = requestEntity.getHeaders();
		assertThat(headers.getAccept()).contains(MediaType.APPLICATION_JSON_UTF8);
		assertThat(headers.getContentType())
				.isEqualTo(MediaType.valueOf(MediaType.APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8"));
		String urlEncodedClientCredential = URLEncoder.encode(clientCredentialWithAnsiKeyboardSpecialCharacters,
				StandardCharsets.UTF_8.toString());
		String clientCredentials = Base64.getEncoder().encodeToString(
				(urlEncodedClientCredential + ":" + urlEncodedClientCredential).getBytes(StandardCharsets.UTF_8));
		assertThat(headers.getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Basic " + clientCredentials);
		MultiValueMap<String, String> formParameters = (MultiValueMap<String, String>) requestEntity.getBody();
		assertThat(formParameters.getFirst(OAuth2ParameterNames.GRANT_TYPE))
				.isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.SCOPE)).contains(clientRegistration.getScopes());
	}

}
