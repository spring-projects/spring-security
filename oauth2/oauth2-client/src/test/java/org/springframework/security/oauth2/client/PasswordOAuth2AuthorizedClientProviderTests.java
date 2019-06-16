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
package org.springframework.security.oauth2.client;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2PasswordGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AccessTokenResponses;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link PasswordOAuth2AuthorizedClientProvider}.
 *
 * @author Joe Grandja
 */
public class PasswordOAuth2AuthorizedClientProviderTests {
	private PasswordOAuth2AuthorizedClientProvider authorizedClientProvider;
	private OAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> accessTokenResponseClient;
	private ClientRegistration clientRegistration;
	private Authentication principal;

	@Before
	public void setup() {
		this.authorizedClientProvider = new PasswordOAuth2AuthorizedClientProvider();
		this.accessTokenResponseClient = mock(OAuth2AccessTokenResponseClient.class);
		this.authorizedClientProvider.setAccessTokenResponseClient(this.accessTokenResponseClient);
		this.clientRegistration = TestClientRegistrations.password().build();
		this.principal = new TestingAuthenticationToken("principal", "password");
	}

	@Test
	public void setAccessTokenResponseClientWhenClientIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientProvider.setAccessTokenResponseClient(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("accessTokenResponseClient cannot be null");
	}

	@Test
	public void authorizeWhenContextIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientProvider.authorize(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("context cannot be null");
	}

	@Test
	public void authorizeWhenNotPasswordThenUnableToAuthorize() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientCredentials().build();

		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.withClientRegistration(clientRegistration)
						.principal(this.principal)
						.build();
		assertThat(this.authorizedClientProvider.authorize(authorizationContext)).isNull();
	}

	@Test
	public void authorizeWhenPasswordAndAuthorizedThenUnableToAuthorize() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				this.clientRegistration, this.principal.getName(), TestOAuth2AccessTokens.scopes("read"));

		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.withAuthorizedClient(authorizedClient)
						.principal(this.principal)
						.build();
		assertThat(this.authorizedClientProvider.authorize(authorizationContext)).isNull();
	}

	@Test
	public void authorizeWhenPasswordAndNotAuthorizedAndEmptyUsernameThenUnableToAuthorize() {
		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.withClientRegistration(this.clientRegistration)
						.principal(this.principal)
						.attribute(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, null)
						.attribute(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, "password")
						.build();
		assertThat(this.authorizedClientProvider.authorize(authorizationContext)).isNull();
	}

	@Test
	public void authorizeWhenPasswordAndNotAuthorizedAndEmptyPasswordThenUnableToAuthorize() {
		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.withClientRegistration(this.clientRegistration)
						.principal(this.principal)
						.attribute(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, "username")
						.attribute(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, null)
						.build();
		assertThat(this.authorizedClientProvider.authorize(authorizationContext)).isNull();
	}

	@Test
	public void authorizeWhenPasswordAndNotAuthorizedThenAuthorize() {
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse().build();
		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(accessTokenResponse);

		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.withClientRegistration(this.clientRegistration)
						.principal(this.principal)
						.attribute(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, "username")
						.attribute(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, "password")
						.build();
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientProvider.authorize(authorizationContext);

		assertThat(authorizedClient.getClientRegistration()).isSameAs(this.clientRegistration);
		assertThat(authorizedClient.getPrincipalName()).isEqualTo(this.principal.getName());
		assertThat(authorizedClient.getAccessToken()).isEqualTo(accessTokenResponse.getAccessToken());
	}
}
