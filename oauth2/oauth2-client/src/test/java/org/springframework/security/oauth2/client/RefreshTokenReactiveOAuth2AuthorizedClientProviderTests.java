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
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.TestOAuth2RefreshTokens;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AccessTokenResponses;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link RefreshTokenReactiveOAuth2AuthorizedClientProvider}.
 *
 * @author Joe Grandja
 */
public class RefreshTokenReactiveOAuth2AuthorizedClientProviderTests {
	private RefreshTokenReactiveOAuth2AuthorizedClientProvider authorizedClientProvider;
	private ReactiveOAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> accessTokenResponseClient;
	private ClientRegistration clientRegistration;
	private Authentication principal;
	private OAuth2AuthorizedClient authorizedClient;

	@Before
	public void setup() {
		this.authorizedClientProvider = new RefreshTokenReactiveOAuth2AuthorizedClientProvider();
		this.accessTokenResponseClient = mock(ReactiveOAuth2AccessTokenResponseClient.class);
		this.authorizedClientProvider.setAccessTokenResponseClient(this.accessTokenResponseClient);
		this.clientRegistration = TestClientRegistrations.clientRegistration().build();
		this.principal = new TestingAuthenticationToken("principal", "password");
		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant expiresAt = issuedAt.plus(Duration.ofMinutes(60));
		OAuth2AccessToken expiredAccessToken = new OAuth2AccessToken(
				OAuth2AccessToken.TokenType.BEARER, "access-token-1234", issuedAt, expiresAt);
		this.authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration, this.principal.getName(),
				expiredAccessToken, TestOAuth2RefreshTokens.refreshToken());
	}

	@Test
	public void setAccessTokenResponseClientWhenClientIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientProvider.setAccessTokenResponseClient(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("accessTokenResponseClient cannot be null");
	}

	@Test
	public void setClockSkewWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientProvider.setClockSkew(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("clockSkew cannot be null");
	}

	@Test
	public void setClockSkewWhenNegativeSecondsThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientProvider.setClockSkew(Duration.ofSeconds(-1)))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("clockSkew must be >= 0");
	}

	@Test
	public void setClockWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientProvider.setClock(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("clock cannot be null");
	}

	@Test
	public void authorizeWhenContextIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientProvider.authorize(null).block())
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("context cannot be null");
	}

	@Test
	public void authorizeWhenNotAuthorizedThenUnableToReauthorize() {
		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.withClientRegistration(this.clientRegistration)
						.principal(this.principal)
						.build();
		assertThat(this.authorizedClientProvider.authorize(authorizationContext).block()).isNull();
	}

	@Test
	public void authorizeWhenAuthorizedAndRefreshTokenIsNullThenUnableToReauthorize() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				this.clientRegistration, this.principal.getName(), this.authorizedClient.getAccessToken());

		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.withAuthorizedClient(authorizedClient)
						.principal(this.principal)
						.build();
		assertThat(this.authorizedClientProvider.authorize(authorizationContext).block()).isNull();
	}

	@Test
	public void authorizeWhenAuthorizedAndAccessTokenNotExpiredThenNotReauthorize() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), TestOAuth2AccessTokens.noScopes(), this.authorizedClient.getRefreshToken());

		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.withAuthorizedClient(authorizedClient)
						.principal(this.principal)
						.build();
		assertThat(this.authorizedClientProvider.authorize(authorizationContext).block()).isNull();
	}

	@Test
	public void authorizeWhenAuthorizedAndAccessTokenExpiredThenReauthorize() {
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse()
				.refreshToken("new-refresh-token")
				.build();
		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(Mono.just(accessTokenResponse));

		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.withAuthorizedClient(this.authorizedClient)
						.principal(this.principal)
						.build();

		OAuth2AuthorizedClient reauthorizedClient = this.authorizedClientProvider.authorize(authorizationContext).block();

		assertThat(reauthorizedClient.getClientRegistration()).isSameAs(this.clientRegistration);
		assertThat(reauthorizedClient.getPrincipalName()).isEqualTo(this.principal.getName());
		assertThat(reauthorizedClient.getAccessToken()).isEqualTo(accessTokenResponse.getAccessToken());
		assertThat(reauthorizedClient.getRefreshToken()).isEqualTo(accessTokenResponse.getRefreshToken());
	}

	@Test
	public void authorizeWhenAuthorizedAndRequestScopeProvidedThenScopeRequested() {
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse()
				.refreshToken("new-refresh-token")
				.build();
		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(Mono.just(accessTokenResponse));

		String[] requestScope = new String[] { "read", "write" };
		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.withAuthorizedClient(this.authorizedClient)
						.principal(this.principal)
						.attribute(OAuth2AuthorizationContext.REQUEST_SCOPE_ATTRIBUTE_NAME, requestScope)
						.build();

		this.authorizedClientProvider.authorize(authorizationContext).block();

		ArgumentCaptor<OAuth2RefreshTokenGrantRequest> refreshTokenGrantRequestArgCaptor =
				ArgumentCaptor.forClass(OAuth2RefreshTokenGrantRequest.class);
		verify(this.accessTokenResponseClient).getTokenResponse(refreshTokenGrantRequestArgCaptor.capture());
		assertThat(refreshTokenGrantRequestArgCaptor.getValue().getScopes()).isEqualTo(new HashSet<>(Arrays.asList(requestScope)));
	}

	@Test
	public void authorizeWhenAuthorizedAndInvalidRequestScopeProvidedThenThrowIllegalArgumentException() {
		String invalidRequestScope = "read write";
		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.withAuthorizedClient(this.authorizedClient)
						.principal(this.principal)
						.attribute(OAuth2AuthorizationContext.REQUEST_SCOPE_ATTRIBUTE_NAME, invalidRequestScope)
						.build();

		assertThatThrownBy(() -> this.authorizedClientProvider.authorize(authorizationContext).block())
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageStartingWith("The context attribute must be of type String[] '" +
						OAuth2AuthorizationContext.REQUEST_SCOPE_ATTRIBUTE_NAME + "'");
	}
}
