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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.TestJwts;
import org.springframework.util.MultiValueMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link JwtBearerGrantRequestEntityConverter}.
 *
 * @author Hassene Laaribi
 * @author Joe Grandja
 */
public class JwtBearerGrantRequestEntityConverterTests {

	private JwtBearerGrantRequestEntityConverter converter;

	@BeforeEach
	public void setup() {
		this.converter = new JwtBearerGrantRequestEntityConverter();
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
		Converter<JwtBearerGrantRequest, HttpHeaders> headersConverter1 = mock(Converter.class);
		this.converter.setHeadersConverter(headersConverter1);
		Converter<JwtBearerGrantRequest, HttpHeaders> headersConverter2 = mock(Converter.class);
		this.converter.addHeadersConverter(headersConverter2);
		// @formatter:off
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration()
				.authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
				.scope("read", "write")
				.build();
		// @formatter:on
		Jwt jwtAssertion = TestJwts.jwt().build();
		JwtBearerGrantRequest jwtBearerGrantRequest = new JwtBearerGrantRequest(clientRegistration, jwtAssertion);
		this.converter.convert(jwtBearerGrantRequest);
		InOrder inOrder = inOrder(headersConverter1, headersConverter2);
		inOrder.verify(headersConverter1).convert(any(JwtBearerGrantRequest.class));
		inOrder.verify(headersConverter2).convert(any(JwtBearerGrantRequest.class));
	}

	@Test
	public void convertWhenParametersConverterSetThenCalled() {
		Converter<JwtBearerGrantRequest, MultiValueMap<String, String>> parametersConverter1 = mock(Converter.class);
		this.converter.setParametersConverter(parametersConverter1);
		Converter<JwtBearerGrantRequest, MultiValueMap<String, String>> parametersConverter2 = mock(Converter.class);
		this.converter.addParametersConverter(parametersConverter2);
		// @formatter:off
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration()
				.authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
				.scope("read", "write")
				.build();
		// @formatter:on
		Jwt jwtAssertion = TestJwts.jwt().build();
		JwtBearerGrantRequest jwtBearerGrantRequest = new JwtBearerGrantRequest(clientRegistration, jwtAssertion);
		this.converter.convert(jwtBearerGrantRequest);
		InOrder inOrder = inOrder(parametersConverter1, parametersConverter2);
		inOrder.verify(parametersConverter1).convert(any(JwtBearerGrantRequest.class));
		inOrder.verify(parametersConverter2).convert(any(JwtBearerGrantRequest.class));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void convertWhenGrantRequestValidThenConverts() {
		// @formatter:off
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration()
				.authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
				.scope("read", "write")
				.build();
		// @formatter:on
		Jwt jwtAssertion = TestJwts.jwt().build();
		JwtBearerGrantRequest jwtBearerGrantRequest = new JwtBearerGrantRequest(clientRegistration, jwtAssertion);
		RequestEntity<?> requestEntity = this.converter.convert(jwtBearerGrantRequest);
		assertThat(requestEntity.getMethod()).isEqualTo(HttpMethod.POST);
		assertThat(requestEntity.getUrl().toASCIIString())
				.isEqualTo(clientRegistration.getProviderDetails().getTokenUri());
		HttpHeaders headers = requestEntity.getHeaders();
		assertThat(headers.getAccept()).contains(MediaType.valueOf(MediaType.APPLICATION_JSON_UTF8_VALUE));
		assertThat(headers.getContentType())
				.isEqualTo(MediaType.valueOf(MediaType.APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8"));
		assertThat(headers.getFirst(HttpHeaders.AUTHORIZATION)).startsWith("Basic ");
		MultiValueMap<String, String> formParameters = (MultiValueMap<String, String>) requestEntity.getBody();
		assertThat(formParameters.getFirst(OAuth2ParameterNames.GRANT_TYPE))
				.isEqualTo(AuthorizationGrantType.JWT_BEARER.getValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.ASSERTION)).isEqualTo(jwtAssertion.getTokenValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.SCOPE)).isEqualTo("read write");
	}

}
