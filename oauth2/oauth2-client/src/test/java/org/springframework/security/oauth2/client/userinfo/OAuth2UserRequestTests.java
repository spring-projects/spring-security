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
package org.springframework.security.oauth2.client.userinfo;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OAuth2UserRequest}.
 *
 * @author Joe Grandja
 */
public class OAuth2UserRequestTests {
	private ClientRegistration clientRegistration;
	private OAuth2AccessToken accessToken;
	private Map<String, Object> additionalParameters;

	@Before
	public void setUp() {
		this.clientRegistration = ClientRegistration.withRegistrationId("registration-1")
				.clientId("client-1")
				.clientSecret("secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri("https://client.com")
				.scope(new LinkedHashSet<>(Arrays.asList("scope1", "scope2")))
				.authorizationUri("https://provider.com/oauth2/authorization")
				.tokenUri("https://provider.com/oauth2/token")
				.clientName("Client 1")
				.build();
		this.accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"access-token-1234", Instant.now(), Instant.now().plusSeconds(60),
				new LinkedHashSet<>(Arrays.asList("scope1", "scope2")));
		this.additionalParameters = new HashMap<>();
		this.additionalParameters.put("param1", "value1");
		this.additionalParameters.put("param2", "value2");
	}

	@Test
	public void constructorWhenClientRegistrationIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2UserRequest(null, this.accessToken))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenAccessTokenIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2UserRequest(this.clientRegistration, null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenAllParametersProvidedAndValidThenCreated() {
		OAuth2UserRequest userRequest = new OAuth2UserRequest(
				this.clientRegistration, this.accessToken, this.additionalParameters);

		assertThat(userRequest.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(userRequest.getAccessToken()).isEqualTo(this.accessToken);
		assertThat(userRequest.getAdditionalParameters()).containsAllEntriesOf(this.additionalParameters);
	}
}
