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
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.MultiValueMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;

/**
 * Tests for {@link OAuth2AuthorizationCodeGrantRequestEntityConverter}.
 *
 * @author Joe Grandja
 */
public class OAuth2AuthorizationCodeGrantRequestEntityConverterTests {
	private OAuth2AuthorizationCodeGrantRequestEntityConverter converter = new OAuth2AuthorizationCodeGrantRequestEntityConverter();
	private OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest;

	@Before
	public void setup() {
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("registration-1")
				.clientId("client-1")
				.clientSecret("secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUriTemplate("https://client.com/callback/client-1")
				.scope("read", "write")
				.authorizationUri("https://provider.com/oauth2/authorize")
				.tokenUri("https://provider.com/oauth2/token")
				.userInfoUri("https://provider.com/user")
				.userNameAttributeName("id")
				.clientName("client-1")
				.build();
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest
				.authorizationCode()
				.clientId(clientRegistration.getClientId())
				.state("state-1234")
				.authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
				.redirectUri(clientRegistration.getRedirectUriTemplate())
				.scopes(clientRegistration.getScopes())
				.build();
		OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponse
				.success("code-1234")
				.state("state-1234")
				.redirectUri(clientRegistration.getRedirectUriTemplate())
				.build();
		OAuth2AuthorizationExchange authorizationExchange =
				new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse);
		this.authorizationCodeGrantRequest = new OAuth2AuthorizationCodeGrantRequest(
				clientRegistration, authorizationExchange);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void convertWhenGrantRequestValidThenConverts() {
		RequestEntity<?> requestEntity = this.converter.convert(this.authorizationCodeGrantRequest);

		ClientRegistration clientRegistration = this.authorizationCodeGrantRequest.getClientRegistration();

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
				AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.CODE)).isEqualTo("code-1234");
		assertThat(formParameters.getFirst(OAuth2ParameterNames.REDIRECT_URI)).isEqualTo(
				clientRegistration.getRedirectUriTemplate());
	}
}
