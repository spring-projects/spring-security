/*
 * Copyright 2002-2018 the original author or authors.
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
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.MultiValueMap;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OAuth2ClientCredentialsGrantRequestEntityConverter}.
 *
 * @author Joe Grandja
 */
public class OAuth2ClientCredentialsGrantRequestEntityConverterTests {

	private OAuth2ClientCredentialsGrantRequestEntityConverter converter = new OAuth2ClientCredentialsGrantRequestEntityConverter();

	private OAuth2ClientCredentialsGrantRequest clientCredentialsGrantRequest;

	@Before
	public void setup() {
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("registration-1")
				.clientId("client-1").clientSecret("secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scope("read", "write")
				.tokenUri("https://provider.com/oauth2/token").build();
		this.clientCredentialsGrantRequest = new OAuth2ClientCredentialsGrantRequest(clientRegistration);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void convertWhenGrantRequestValidThenConverts() {
		RequestEntity<?> requestEntity = this.converter.convert(this.clientCredentialsGrantRequest);

		ClientRegistration clientRegistration = this.clientCredentialsGrantRequest.getClientRegistration();

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
		assertThat(formParameters.getFirst(OAuth2ParameterNames.SCOPE)).isEqualTo("read write");
	}

}
