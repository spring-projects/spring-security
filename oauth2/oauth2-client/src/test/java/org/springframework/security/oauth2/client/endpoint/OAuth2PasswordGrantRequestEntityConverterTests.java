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

import org.junit.Before;
import org.junit.Test;

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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link OAuth2PasswordGrantRequestEntityConverter}.
 *
 * @author Joe Grandja
 */
public class OAuth2PasswordGrantRequestEntityConverterTests {

	private OAuth2PasswordGrantRequestEntityConverter converter;

	@Before
	public void setup() {
		this.converter = new OAuth2PasswordGrantRequestEntityConverter();
	}

	@Test
	public void setCustomizerWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.converter.setCustomizer(null))
				.withMessage("customizer cannot be null");
	}

	@Test
	public void convertWhenCustomizerSetThenCalled() {
		OAuth2AuthorizationGrantRequestEntityConverter.Customizer<OAuth2PasswordGrantRequest> customizer = mock(
				OAuth2AuthorizationGrantRequestEntityConverter.Customizer.class);
		this.converter.setCustomizer(customizer);
		ClientRegistration clientRegistration = TestClientRegistrations.password().build();
		OAuth2PasswordGrantRequest passwordGrantRequest = new OAuth2PasswordGrantRequest(clientRegistration, "user1",
				"password");
		this.converter.convert(passwordGrantRequest);
		verify(customizer).customize(any(OAuth2PasswordGrantRequest.class), any(HttpHeaders.class),
				any(MultiValueMap.class));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void convertWhenGrantRequestValidThenConverts() {
		ClientRegistration clientRegistration = TestClientRegistrations.password().build();
		OAuth2PasswordGrantRequest passwordGrantRequest = new OAuth2PasswordGrantRequest(clientRegistration, "user1",
				"password");
		RequestEntity<?> requestEntity = this.converter.convert(passwordGrantRequest);
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
				.isEqualTo(AuthorizationGrantType.PASSWORD.getValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.USERNAME)).isEqualTo("user1");
		assertThat(formParameters.getFirst(OAuth2ParameterNames.PASSWORD)).isEqualTo("password");
		assertThat(formParameters.getFirst(OAuth2ParameterNames.SCOPE)).contains(clientRegistration.getScopes());
	}

}
