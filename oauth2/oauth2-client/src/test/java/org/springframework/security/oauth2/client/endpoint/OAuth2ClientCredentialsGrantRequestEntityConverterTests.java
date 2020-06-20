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
import org.springframework.security.oauth2.core.endpoint.ClientAssertionParameterNames;
import org.springframework.security.oauth2.core.endpoint.ClientAssertionParameterValues;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.MultiValueMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;

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
				.clientId("client-1")
				.clientSecret("secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.scope("read", "write")
				.tokenUri("https://provider.com/oauth2/token")
				.build();
		this.clientCredentialsGrantRequest = new OAuth2ClientCredentialsGrantRequest(clientRegistration);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void convertWhenGrantRequestValidThenConverts() {
		RequestEntity<?> requestEntity = this.converter.convert(this.clientCredentialsGrantRequest);

		ClientRegistration clientRegistration = this.clientCredentialsGrantRequest.getClientRegistration();

		assertThat(requestEntity.getMethod()).isEqualTo(HttpMethod.POST);
		assertThat(requestEntity.getUrl().toASCIIString()).isEqualTo(
				clientRegistration.getProviderDetails().getTokenUri());

		HttpHeaders headers = requestEntity.getHeaders();
		assertThat(headers.getAccept()).contains(MediaType.APPLICATION_JSON_UTF8);
		assertThat(headers.getContentType()).isEqualTo(
				MediaType.valueOf(APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8"));
		assertThat(headers.getFirst(HttpHeaders.AUTHORIZATION)).startsWith("Basic ");

		MultiValueMap<String, String> formParameters = (MultiValueMap<String, String>) requestEntity.getBody();
		assertThat(formParameters.getFirst(OAuth2ParameterNames.GRANT_TYPE)).isEqualTo(
				AuthorizationGrantType.CLIENT_CREDENTIALS.getValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.SCOPE)).isEqualTo("read write");
	}
	@SuppressWarnings("unchecked")
	@Test
	public void convertWhenGrantRequestSecretJWTValidThenConverts() {

		ClientRegistration clientRegistration = this.from(this.clientCredentialsGrantRequest.getClientRegistration())
				.clientAuthenticationMethod(ClientAuthenticationMethod.SECRET_JWT)
				.clientSecret("2ae2135579004d5d87ae8241603c0a5c")
				.build();

		OAuth2ClientCredentialsGrantRequest clientCredentialsGrantRequest = new OAuth2ClientCredentialsGrantRequest(clientRegistration);
		RequestEntity<?> requestEntity = this.converter.convert(clientCredentialsGrantRequest);

		assertThat(requestEntity.getMethod()).isEqualTo(HttpMethod.POST);
		assertThat(requestEntity.getUrl().toASCIIString()).isEqualTo(
				clientRegistration.getProviderDetails().getTokenUri());

		HttpHeaders headers = requestEntity.getHeaders();
		assertThat(headers.getAccept()).contains(MediaType.APPLICATION_JSON_UTF8);
		assertThat(headers.getContentType()).isEqualTo(
				MediaType.valueOf(APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8"));

		MultiValueMap<String, String> formParameters = (MultiValueMap<String, String>) requestEntity.getBody();
		assertThat(formParameters.getFirst(OAuth2ParameterNames.GRANT_TYPE)).isEqualTo(
				AuthorizationGrantType.CLIENT_CREDENTIALS.getValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.SCOPE)).isEqualTo("read write");
		assertThat(formParameters.getFirst(ClientAssertionParameterNames.CLIENT_ASSERTION)).isNotEmpty();
		assertThat(formParameters.getFirst(ClientAssertionParameterNames.CLIENT_ASSERTION_TYPE)).isEqualTo(
				ClientAssertionParameterValues.CLIENT_ASSERTION_TYPE_JWT_BEARER);
	}


	private ClientRegistration.Builder from(ClientRegistration registration) {
		return ClientRegistration.withRegistrationId(registration.getRegistrationId())
				.clientId(registration.getClientId())
				.clientSecret(registration.getClientSecret())
				.clientAuthenticationMethod(registration.getClientAuthenticationMethod())
				.authorizationGrantType(registration.getAuthorizationGrantType())
				.redirectUriTemplate(registration.getRedirectUriTemplate())
				.scope(registration.getScopes())
				.authorizationUri(registration.getProviderDetails().getAuthorizationUri())
				.tokenUri(registration.getProviderDetails().getTokenUri())
				.userInfoUri(registration.getProviderDetails().getUserInfoEndpoint().getUri())
				.userNameAttributeName(registration.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName())
				.clientName(registration.getClientName());
	}
}
