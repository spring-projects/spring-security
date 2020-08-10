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
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.endpoint.DefaultClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.DefaultPasswordTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.DefaultRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.TestOAuth2RefreshTokens;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AccessTokenResponses;
import org.springframework.web.client.RestOperations;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link OAuth2AuthorizedClientProviderBuilder}.
 *
 * @author Joe Grandja
 */
public class OAuth2AuthorizedClientProviderBuilderTests {

	private RestOperations accessTokenClient;

	private DefaultClientCredentialsTokenResponseClient clientCredentialsTokenResponseClient;

	private DefaultRefreshTokenTokenResponseClient refreshTokenTokenResponseClient;

	private DefaultPasswordTokenResponseClient passwordTokenResponseClient;

	private Authentication principal;

	@SuppressWarnings("unchecked")
	@Before
	public void setup() {
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse().build();
		this.accessTokenClient = mock(RestOperations.class);
		when(this.accessTokenClient.exchange(any(RequestEntity.class), eq(OAuth2AccessTokenResponse.class)))
				.thenReturn(new ResponseEntity(accessTokenResponse, HttpStatus.OK));
		this.refreshTokenTokenResponseClient = new DefaultRefreshTokenTokenResponseClient();
		this.refreshTokenTokenResponseClient.setRestOperations(this.accessTokenClient);
		this.clientCredentialsTokenResponseClient = new DefaultClientCredentialsTokenResponseClient();
		this.clientCredentialsTokenResponseClient.setRestOperations(this.accessTokenClient);
		this.passwordTokenResponseClient = new DefaultPasswordTokenResponseClient();
		this.passwordTokenResponseClient.setRestOperations(this.accessTokenClient);
		this.principal = new TestingAuthenticationToken("principal", "password");
	}

	@Test
	public void providerWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OAuth2AuthorizedClientProviderBuilder.builder().provider(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenAuthorizationCodeProviderThenProviderAuthorizes() {
		OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
				.authorizationCode().build();

		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(TestClientRegistrations.clientRegistration().build()).principal(this.principal)
				.build();
		assertThatThrownBy(() -> authorizedClientProvider.authorize(authorizationContext))
				.isInstanceOf(ClientAuthorizationRequiredException.class);
	}

	@Test
	public void buildWhenRefreshTokenProviderThenProviderReauthorizes() {
		OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
				.refreshToken(configurer -> configurer.accessTokenResponseClient(this.refreshTokenTokenResponseClient))
				.build();

		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				TestClientRegistrations.clientRegistration().build(), this.principal.getName(), expiredAccessToken(),
				TestOAuth2RefreshTokens.refreshToken());

		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withAuthorizedClient(authorizedClient).principal(this.principal).build();
		OAuth2AuthorizedClient reauthorizedClient = authorizedClientProvider.authorize(authorizationContext);

		assertThat(reauthorizedClient).isNotNull();
		verify(this.accessTokenClient).exchange(any(RequestEntity.class), eq(OAuth2AccessTokenResponse.class));
	}

	@Test
	public void buildWhenClientCredentialsProviderThenProviderAuthorizes() {
		OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
				.clientCredentials(
						configurer -> configurer.accessTokenResponseClient(this.clientCredentialsTokenResponseClient))
				.build();

		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(TestClientRegistrations.clientCredentials().build()).principal(this.principal)
				.build();
		OAuth2AuthorizedClient authorizedClient = authorizedClientProvider.authorize(authorizationContext);

		assertThat(authorizedClient).isNotNull();
		verify(this.accessTokenClient).exchange(any(RequestEntity.class), eq(OAuth2AccessTokenResponse.class));
	}

	@Test
	public void buildWhenPasswordProviderThenProviderAuthorizes() {
		OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
				.password(configurer -> configurer.accessTokenResponseClient(this.passwordTokenResponseClient)).build();

		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(TestClientRegistrations.password().build()).principal(this.principal)
				.attribute(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, "username")
				.attribute(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, "password").build();
		OAuth2AuthorizedClient authorizedClient = authorizedClientProvider.authorize(authorizationContext);

		assertThat(authorizedClient).isNotNull();
		verify(this.accessTokenClient).exchange(any(RequestEntity.class), eq(OAuth2AccessTokenResponse.class));
	}

	@Test
	public void buildWhenAllProvidersThenProvidersAuthorize() {
		OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
				.authorizationCode()
				.refreshToken(configurer -> configurer.accessTokenResponseClient(this.refreshTokenTokenResponseClient))
				.clientCredentials(
						configurer -> configurer.accessTokenResponseClient(this.clientCredentialsTokenResponseClient))
				.password(configurer -> configurer.accessTokenResponseClient(this.passwordTokenResponseClient)).build();

		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();

		// authorization_code
		OAuth2AuthorizationContext authorizationCodeContext = OAuth2AuthorizationContext
				.withClientRegistration(clientRegistration).principal(this.principal).build();
		assertThatThrownBy(() -> authorizedClientProvider.authorize(authorizationCodeContext))
				.isInstanceOf(ClientAuthorizationRequiredException.class);

		// refresh_token
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(clientRegistration,
				this.principal.getName(), expiredAccessToken(), TestOAuth2RefreshTokens.refreshToken());

		OAuth2AuthorizationContext refreshTokenContext = OAuth2AuthorizationContext
				.withAuthorizedClient(authorizedClient).principal(this.principal).build();
		OAuth2AuthorizedClient reauthorizedClient = authorizedClientProvider.authorize(refreshTokenContext);

		assertThat(reauthorizedClient).isNotNull();
		verify(this.accessTokenClient, times(1)).exchange(any(RequestEntity.class),
				eq(OAuth2AccessTokenResponse.class));

		// client_credentials
		OAuth2AuthorizationContext clientCredentialsContext = OAuth2AuthorizationContext
				.withClientRegistration(TestClientRegistrations.clientCredentials().build()).principal(this.principal)
				.build();
		authorizedClient = authorizedClientProvider.authorize(clientCredentialsContext);

		assertThat(authorizedClient).isNotNull();
		verify(this.accessTokenClient, times(2)).exchange(any(RequestEntity.class),
				eq(OAuth2AccessTokenResponse.class));

		// password
		OAuth2AuthorizationContext passwordContext = OAuth2AuthorizationContext
				.withClientRegistration(TestClientRegistrations.password().build()).principal(this.principal)
				.attribute(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, "username")
				.attribute(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, "password").build();
		authorizedClient = authorizedClientProvider.authorize(passwordContext);

		assertThat(authorizedClient).isNotNull();
		verify(this.accessTokenClient, times(3)).exchange(any(RequestEntity.class),
				eq(OAuth2AccessTokenResponse.class));
	}

	@Test
	public void buildWhenCustomProviderThenProviderCalled() {
		OAuth2AuthorizedClientProvider customProvider = mock(OAuth2AuthorizedClientProvider.class);

		OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
				.provider(customProvider).build();

		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(TestClientRegistrations.clientRegistration().build()).principal(this.principal)
				.build();
		authorizedClientProvider.authorize(authorizationContext);

		verify(customProvider).authorize(any(OAuth2AuthorizationContext.class));
	}

	private OAuth2AccessToken expiredAccessToken() {
		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant expiresAt = issuedAt.plus(Duration.ofMinutes(60));
		return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token-1234", issuedAt, expiresAt);
	}

}
