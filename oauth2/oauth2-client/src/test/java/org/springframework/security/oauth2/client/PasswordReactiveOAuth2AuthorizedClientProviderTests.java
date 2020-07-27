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

import java.time.Duration;
import java.time.Instant;

import org.junit.Before;
import org.junit.Test;
import reactor.core.publisher.Mono;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.endpoint.OAuth2PasswordGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.TestOAuth2RefreshTokens;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AccessTokenResponses;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link PasswordReactiveOAuth2AuthorizedClientProvider}.
 *
 * @author Joe Grandja
 */
public class PasswordReactiveOAuth2AuthorizedClientProviderTests {

	private PasswordReactiveOAuth2AuthorizedClientProvider authorizedClientProvider;

	private ReactiveOAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> accessTokenResponseClient;

	private ClientRegistration clientRegistration;

	private Authentication principal;

	@Before
	public void setup() {
		this.authorizedClientProvider = new PasswordReactiveOAuth2AuthorizedClientProvider();
		this.accessTokenResponseClient = mock(ReactiveOAuth2AccessTokenResponseClient.class);
		this.authorizedClientProvider.setAccessTokenResponseClient(this.accessTokenResponseClient);
		this.clientRegistration = TestClientRegistrations.password().build();
		this.principal = new TestingAuthenticationToken("principal", "password");
	}

	@Test
	public void setAccessTokenResponseClientWhenClientIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientProvider.setAccessTokenResponseClient(null))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("accessTokenResponseClient cannot be null");
	}

	@Test
	public void setClockSkewWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientProvider.setClockSkew(null))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("clockSkew cannot be null");
	}

	@Test
	public void setClockSkewWhenNegativeSecondsThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientProvider.setClockSkew(Duration.ofSeconds(-1)))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("clockSkew must be >= 0");
	}

	@Test
	public void setClockWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientProvider.setClock(null))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("clock cannot be null");
	}

	@Test
	public void authorizeWhenContextIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientProvider.authorize(null).block())
				.isInstanceOf(IllegalArgumentException.class).hasMessage("context cannot be null");
	}

	@Test
	public void authorizeWhenNotPasswordThenUnableToAuthorize() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientCredentials().build();

		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(clientRegistration).principal(this.principal).build();
		assertThat(this.authorizedClientProvider.authorize(authorizationContext).block()).isNull();
	}

	@Test
	public void authorizeWhenPasswordAndNotAuthorizedAndEmptyUsernameThenUnableToAuthorize() {
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(this.clientRegistration).principal(this.principal)
				.attribute(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, null)
				.attribute(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, "password").build();
		assertThat(this.authorizedClientProvider.authorize(authorizationContext).block()).isNull();
	}

	@Test
	public void authorizeWhenPasswordAndNotAuthorizedAndEmptyPasswordThenUnableToAuthorize() {
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(this.clientRegistration).principal(this.principal)
				.attribute(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, "username")
				.attribute(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, null).build();
		assertThat(this.authorizedClientProvider.authorize(authorizationContext).block()).isNull();
	}

	@Test
	public void authorizeWhenPasswordAndNotAuthorizedThenAuthorize() {
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse().build();
		given(this.accessTokenResponseClient.getTokenResponse(any())).willReturn(Mono.just(accessTokenResponse));

		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(this.clientRegistration).principal(this.principal)
				.attribute(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, "username")
				.attribute(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, "password").build();
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientProvider.authorize(authorizationContext).block();

		assertThat(authorizedClient.getClientRegistration()).isSameAs(this.clientRegistration);
		assertThat(authorizedClient.getPrincipalName()).isEqualTo(this.principal.getName());
		assertThat(authorizedClient.getAccessToken()).isEqualTo(accessTokenResponse.getAccessToken());
	}

	@Test
	public void authorizeWhenPasswordAndAuthorizedWithoutRefreshTokenAndTokenExpiredThenReauthorize() {
		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant expiresAt = issuedAt.plus(Duration.ofMinutes(60));
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"access-token-expired", issuedAt, expiresAt);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), accessToken); // without refresh token

		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse().build();
		given(this.accessTokenResponseClient.getTokenResponse(any())).willReturn(Mono.just(accessTokenResponse));

		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withAuthorizedClient(authorizedClient)
				.attribute(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, "username")
				.attribute(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, "password").principal(this.principal)
				.build();
		authorizedClient = this.authorizedClientProvider.authorize(authorizationContext).block();

		assertThat(authorizedClient.getClientRegistration()).isSameAs(this.clientRegistration);
		assertThat(authorizedClient.getPrincipalName()).isEqualTo(this.principal.getName());
		assertThat(authorizedClient.getAccessToken()).isEqualTo(accessTokenResponse.getAccessToken());

	}

	@Test
	public void authorizeWhenPasswordAndAuthorizedWithRefreshTokenAndTokenExpiredThenNotReauthorize() {
		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant expiresAt = issuedAt.plus(Duration.ofMinutes(60));
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"access-token-expired", issuedAt, expiresAt);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), accessToken, TestOAuth2RefreshTokens.refreshToken()); // with
																								// refresh
																								// token

		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withAuthorizedClient(authorizedClient)
				.attribute(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, "username")
				.attribute(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, "password").principal(this.principal)
				.build();
		assertThat(this.authorizedClientProvider.authorize(authorizationContext).block()).isNull();
	}

	// gh-7511
	@Test
	public void authorizeWhenPasswordAndAuthorizedAndTokenNotExpiredButClockSkewForcesExpiryThenReauthorize() {
		Instant now = Instant.now();
		Instant issuedAt = now.minus(Duration.ofMinutes(60));
		Instant expiresAt = now.minus(Duration.ofMinutes(1));
		OAuth2AccessToken expiresInOneMinAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"access-token-1234", issuedAt, expiresAt);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), expiresInOneMinAccessToken); // without refresh
																		// token

		// Shorten the lifespan of the access token by 90 seconds, which will ultimately
		// force it to expire on the client
		this.authorizedClientProvider.setClockSkew(Duration.ofSeconds(90));

		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse().build();
		given(this.accessTokenResponseClient.getTokenResponse(any())).willReturn(Mono.just(accessTokenResponse));

		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withAuthorizedClient(authorizedClient)
				.attribute(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, "username")
				.attribute(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, "password").principal(this.principal)
				.build();

		OAuth2AuthorizedClient reauthorizedClient = this.authorizedClientProvider.authorize(authorizationContext)
				.block();

		assertThat(reauthorizedClient.getClientRegistration()).isSameAs(this.clientRegistration);
		assertThat(reauthorizedClient.getPrincipalName()).isEqualTo(this.principal.getName());
		assertThat(reauthorizedClient.getAccessToken()).isEqualTo(accessTokenResponse.getAccessToken());
	}

}
