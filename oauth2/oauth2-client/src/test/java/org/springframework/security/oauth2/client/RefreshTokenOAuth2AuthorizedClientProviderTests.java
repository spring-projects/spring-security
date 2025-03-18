/*
 * Copyright 2002-2025 the original author or authors.
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
import java.util.Arrays;
import java.util.HashSet;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.event.OAuth2AuthorizedClientRefreshedEvent;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.TestOAuth2RefreshTokens;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AccessTokenResponses;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link RefreshTokenOAuth2AuthorizedClientProvider}.
 *
 * @author Joe Grandja
 */
public class RefreshTokenOAuth2AuthorizedClientProviderTests {

	private RefreshTokenOAuth2AuthorizedClientProvider authorizedClientProvider;

	private OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> accessTokenResponseClient;

	private ClientRegistration clientRegistration;

	private Authentication principal;

	private OAuth2AuthorizedClient authorizedClient;

	@BeforeEach
	public void setup() {
		this.authorizedClientProvider = new RefreshTokenOAuth2AuthorizedClientProvider();
		this.accessTokenResponseClient = mock(OAuth2AccessTokenResponseClient.class);
		this.authorizedClientProvider.setAccessTokenResponseClient(this.accessTokenResponseClient);
		this.clientRegistration = TestClientRegistrations.clientRegistration().build();
		this.principal = new TestingAuthenticationToken("principal", "password");
		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant expiresAt = issuedAt.plus(Duration.ofMinutes(60));
		OAuth2AccessToken expiredAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"access-token-1234", issuedAt, expiresAt);
		this.authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration, this.principal.getName(),
				expiredAccessToken, TestOAuth2RefreshTokens.refreshToken());
	}

	@Test
	public void setAccessTokenResponseClientWhenClientIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizedClientProvider.setAccessTokenResponseClient(null))
				.withMessage("accessTokenResponseClient cannot be null");
		// @formatter:on
	}

	@Test
	public void setClockSkewWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizedClientProvider.setClockSkew(null))
				.withMessage("clockSkew cannot be null");
		// @formatter:on
	}

	@Test
	public void setClockSkewWhenNegativeSecondsThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizedClientProvider.setClockSkew(Duration.ofSeconds(-1)))
				.withMessage("clockSkew must be >= 0");
		// @formatter:on
	}

	@Test
	public void setClockWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizedClientProvider.setClock(null))
				.withMessage("clock cannot be null");
		// @formatter:on
	}

	@Test
	public void authorizeWhenContextIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizedClientProvider.authorize(null))
				.withMessage("context cannot be null");
		// @formatter:on
	}

	@Test
	public void authorizeWhenNotAuthorizedThenUnableToReauthorize() {
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(this.clientRegistration)
				.principal(this.principal)
				.build();
		// @formatter:on
		assertThat(this.authorizedClientProvider.authorize(authorizationContext)).isNull();
	}

	@Test
	public void authorizeWhenAuthorizedAndRefreshTokenIsNullThenUnableToReauthorize() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), this.authorizedClient.getAccessToken());
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withAuthorizedClient(authorizedClient)
				.principal(this.principal)
				.build();
		// @formatter:on
		assertThat(this.authorizedClientProvider.authorize(authorizationContext)).isNull();
	}

	@Test
	public void authorizeWhenAuthorizedAndAccessTokenNotExpiredThenNotReauthorize() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), TestOAuth2AccessTokens.noScopes(), this.authorizedClient.getRefreshToken());
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withAuthorizedClient(authorizedClient)
				.principal(this.principal)
				.build();
		// @formatter:on
		assertThat(this.authorizedClientProvider.authorize(authorizationContext)).isNull();
	}

	// gh-7511
	@Test
	public void authorizeWhenAuthorizedAndAccessTokenNotExpiredButClockSkewForcesExpiryThenReauthorize() {
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse()
			.refreshToken("new-refresh-token")
			.build();
		given(this.accessTokenResponseClient.getTokenResponse(any())).willReturn(accessTokenResponse);
		Instant now = Instant.now();
		Instant issuedAt = now.minus(Duration.ofMinutes(60));
		Instant expiresAt = now.minus(Duration.ofMinutes(1));
		OAuth2AccessToken expiresInOneMinAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"access-token-1234", issuedAt, expiresAt);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), expiresInOneMinAccessToken, this.authorizedClient.getRefreshToken());
		// Shorten the lifespan of the access token by 90 seconds, which will ultimately
		// force it to expire on the client
		this.authorizedClientProvider.setClockSkew(Duration.ofSeconds(90));
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withAuthorizedClient(authorizedClient)
				.principal(this.principal)
				.build();
		// @formatter:on
		OAuth2AuthorizedClient reauthorizedClient = this.authorizedClientProvider.authorize(authorizationContext);
		assertThat(reauthorizedClient.getClientRegistration()).isSameAs(this.clientRegistration);
		assertThat(reauthorizedClient.getPrincipalName()).isEqualTo(this.principal.getName());
		assertThat(reauthorizedClient.getAccessToken()).isEqualTo(accessTokenResponse.getAccessToken());
		assertThat(reauthorizedClient.getRefreshToken()).isEqualTo(accessTokenResponse.getRefreshToken());
	}

	@Test
	public void authorizeWhenAuthorizedAndAccessTokenExpiredThenReauthorize() {
		// @formatter:off
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses
				.accessTokenResponse()
				.refreshToken("new-refresh-token")
				.build();
		// @formatter:on
		given(this.accessTokenResponseClient.getTokenResponse(any())).willReturn(accessTokenResponse);
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withAuthorizedClient(this.authorizedClient)
				.principal(this.principal)
				.build();
		// @formatter:on
		OAuth2AuthorizedClient reauthorizedClient = this.authorizedClientProvider.authorize(authorizationContext);
		assertThat(reauthorizedClient.getClientRegistration()).isSameAs(this.clientRegistration);
		assertThat(reauthorizedClient.getPrincipalName()).isEqualTo(this.principal.getName());
		assertThat(reauthorizedClient.getAccessToken()).isEqualTo(accessTokenResponse.getAccessToken());
		assertThat(reauthorizedClient.getRefreshToken()).isEqualTo(accessTokenResponse.getRefreshToken());
	}

	@Test
	public void authorizeWhenAuthorizedAndRequestScopeProvidedThenScopeRequested() {
		// @formatter:off
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses
				.accessTokenResponse()
				.refreshToken("new-refresh-token")
				.build();
		// @formatter:on
		given(this.accessTokenResponseClient.getTokenResponse(any())).willReturn(accessTokenResponse);
		String[] requestScope = new String[] { "read", "write" };
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withAuthorizedClient(this.authorizedClient)
				.principal(this.principal)
				.attribute(OAuth2AuthorizationContext.REQUEST_SCOPE_ATTRIBUTE_NAME, requestScope)
				.build();
		// @formatter:on
		this.authorizedClientProvider.authorize(authorizationContext);
		ArgumentCaptor<OAuth2RefreshTokenGrantRequest> refreshTokenGrantRequestArgCaptor = ArgumentCaptor
			.forClass(OAuth2RefreshTokenGrantRequest.class);
		verify(this.accessTokenResponseClient).getTokenResponse(refreshTokenGrantRequestArgCaptor.capture());
		assertThat(refreshTokenGrantRequestArgCaptor.getValue().getScopes())
			.isEqualTo(new HashSet<>(Arrays.asList(requestScope)));
	}

	@Test
	public void authorizeWhenAuthorizedAndInvalidRequestScopeProvidedThenThrowIllegalArgumentException() {
		String invalidRequestScope = "read write";
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withAuthorizedClient(this.authorizedClient)
				.principal(this.principal)
				.attribute(OAuth2AuthorizationContext.REQUEST_SCOPE_ATTRIBUTE_NAME, invalidRequestScope)
				.build();
		// @formatter:on
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.authorizedClientProvider.authorize(authorizationContext))
			.withMessageStartingWith("The context attribute must be of type String[] '"
					+ OAuth2AuthorizationContext.REQUEST_SCOPE_ATTRIBUTE_NAME + "'");
	}

	@Test
	public void shouldPublishEventWhenTokenRefreshed() {
		OAuth2TokenRefreshedAwareEventPublisher eventPublisher = new OAuth2TokenRefreshedAwareEventPublisher();
		this.authorizedClientProvider.setApplicationEventPublisher(eventPublisher);
		// @formatter:off
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses
				.accessTokenResponse()
				.refreshToken("new-refresh-token")
				.build();
		// @formatter:on
		given(this.accessTokenResponseClient.getTokenResponse(any())).willReturn(accessTokenResponse);
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withAuthorizedClient(this.authorizedClient)
				.principal(this.principal)
				.build();
		// @formatter:on
		this.authorizedClientProvider.authorize(authorizationContext);
		assertThat(eventPublisher.flag).isTrue();
	}

	@Test
	public void shouldNotPublishEventWhenTokenNotRefreshed() {
		OAuth2TokenRefreshedAwareEventPublisher eventPublisher = new OAuth2TokenRefreshedAwareEventPublisher();
		this.authorizedClientProvider.setApplicationEventPublisher(eventPublisher);

		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), TestOAuth2AccessTokens.noScopes(), this.authorizedClient.getRefreshToken());
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withAuthorizedClient(authorizedClient)
				.principal(this.principal)
				.build();
		// @formatter:on
		this.authorizedClientProvider.authorize(authorizationContext);
		assertThat(eventPublisher.flag).isFalse();
	}

	private static class OAuth2TokenRefreshedAwareEventPublisher implements ApplicationEventPublisher {

		Boolean flag = false;

		@Override
		public void publishEvent(Object event) {
			if (OAuth2AuthorizedClientRefreshedEvent.class.isAssignableFrom(event.getClass())) {
				this.flag = true;
			}
		}

	}

}
