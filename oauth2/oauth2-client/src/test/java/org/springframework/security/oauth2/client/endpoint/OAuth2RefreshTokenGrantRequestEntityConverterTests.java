/*
 * Copyright 2002-2019 the original author or authors.
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
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.ClientAssertionParameterNames;
import org.springframework.security.oauth2.core.endpoint.ClientAssertionParameterValues;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.MultiValueMap;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;

/**
 * Tests for {@link OAuth2RefreshTokenGrantRequestEntityConverter}.
 *
 * @author Joe Grandja
 */
public class OAuth2RefreshTokenGrantRequestEntityConverterTests {
	private OAuth2RefreshTokenGrantRequestEntityConverter converter = new OAuth2RefreshTokenGrantRequestEntityConverter();
	private OAuth2RefreshTokenGrantRequest refreshTokenGrantRequest;

	@Before
	public void setup() {
		this.refreshTokenGrantRequest = new OAuth2RefreshTokenGrantRequest(
				TestClientRegistrations.clientRegistration().build(),
				TestOAuth2AccessTokens.scopes("read", "write"),
				TestOAuth2RefreshTokens.refreshToken(),
				Collections.singleton("read"));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void convertWhenGrantRequestValidThenConverts() {
		RequestEntity<?> requestEntity = this.converter.convert(this.refreshTokenGrantRequest);

		ClientRegistration clientRegistration = this.refreshTokenGrantRequest.getClientRegistration();
		OAuth2RefreshToken refreshToken = this.refreshTokenGrantRequest.getRefreshToken();

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
				AuthorizationGrantType.REFRESH_TOKEN.getValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.REFRESH_TOKEN)).isEqualTo(
				refreshToken.getTokenValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.SCOPE)).isEqualTo("read");
	}
	@SuppressWarnings("unchecked")
	@Test
	public void convertWhenGrantRequestJWTSecretValidThenConverts() {

		ClientRegistration clientRegistration = this.from(this.refreshTokenGrantRequest.getClientRegistration())
				.clientAuthenticationMethod(ClientAuthenticationMethod.SECRET_JWT)
				.clientSecret("2ae2135579004d5d87ae8241603c0a5c")
				.build();

		OAuth2RefreshTokenGrantRequest refreshTokenGrantRequest = new OAuth2RefreshTokenGrantRequest(
				clientRegistration,
				TestOAuth2AccessTokens.scopes("read", "write"),
				TestOAuth2RefreshTokens.refreshToken(),
				Collections.singleton("read"));
		RequestEntity<?> requestEntity = this.converter.convert(refreshTokenGrantRequest);

		OAuth2RefreshToken refreshToken = this.refreshTokenGrantRequest.getRefreshToken();

		assertThat(requestEntity.getMethod()).isEqualTo(HttpMethod.POST);
		assertThat(requestEntity.getUrl().toASCIIString()).isEqualTo(
				clientRegistration.getProviderDetails().getTokenUri());

		HttpHeaders headers = requestEntity.getHeaders();
		assertThat(headers.getAccept()).contains(MediaType.APPLICATION_JSON_UTF8);
		assertThat(headers.getContentType()).isEqualTo(
				MediaType.valueOf(APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8"));

		MultiValueMap<String, String> formParameters = (MultiValueMap<String, String>) requestEntity.getBody();
		assertThat(formParameters.getFirst(OAuth2ParameterNames.GRANT_TYPE)).isEqualTo(
				AuthorizationGrantType.REFRESH_TOKEN.getValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.REFRESH_TOKEN)).isEqualTo(
				refreshToken.getTokenValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.SCOPE)).isEqualTo("read");
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
