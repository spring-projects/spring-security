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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AccessTokenResponses;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link ClientCredentialsReactiveOAuth2AuthorizedClientProvider}.
 *
 * @author Joe Grandja
 */
public class ClientCredentialsReactiveOAuth2AuthorizedClientProviderTests {

	private ClientCredentialsReactiveOAuth2AuthorizedClientProvider authorizedClientProvider;

	private ReactiveOAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> accessTokenResponseClient;

	private ClientRegistration clientRegistration;

	private Authentication principal;

	@BeforeEach
	public void setup() {
		this.authorizedClientProvider = new ClientCredentialsReactiveOAuth2AuthorizedClientProvider();
		this.accessTokenResponseClient = mock(ReactiveOAuth2AccessTokenResponseClient.class);
		this.authorizedClientProvider.setAccessTokenResponseClient(this.accessTokenResponseClient);
		this.clientRegistration = TestClientRegistrations.clientCredentials().build();
		this.principal = new TestingAuthenticationToken("principal", "password");
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
				.isThrownBy(() -> this.authorizedClientProvider.authorize(null).block())
				.withMessage("context cannot be null");
		// @formatter:on
	}

	@Test
	public void authorizeWhenNotClientCredentialsThenUnableToAuthorize() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(clientRegistration)
				.principal(this.principal)
				.build();
		// @formatter:on
		assertThat(this.authorizedClientProvider.authorize(authorizationContext).block()).isNull();
	}

	@Test
	public void authorizeWhenClientCredentialsAndNotAuthorizedThenAuthorize() {
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse().build();
		given(this.accessTokenResponseClient.getTokenResponse(any())).willReturn(Mono.just(accessTokenResponse));
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(this.clientRegistration)
				.principal(this.principal)
				.build();
		// @formatter:on
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientProvider.authorize(authorizationContext).block();
		assertThat(authorizedClient.getClientRegistration()).isSameAs(this.clientRegistration);
		assertThat(authorizedClient.getPrincipalName()).isEqualTo(this.principal.getName());
		assertThat(authorizedClient.getAccessToken()).isEqualTo(accessTokenResponse.getAccessToken());
	}

	@Test
	public void authorizeWhenClientCredentialsAndTokenExpiredThenReauthorize() {
		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant expiresAt = issuedAt.plus(Duration.ofMinutes(60));
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token-1234",
				issuedAt, expiresAt);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), accessToken);
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse().build();
		given(this.accessTokenResponseClient.getTokenResponse(any())).willReturn(Mono.just(accessTokenResponse));
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withAuthorizedClient(authorizedClient)
				.principal(this.principal)
				.build();
		// @formatter:on
		authorizedClient = this.authorizedClientProvider.authorize(authorizationContext).block();
		assertThat(authorizedClient.getClientRegistration()).isSameAs(this.clientRegistration);
		assertThat(authorizedClient.getPrincipalName()).isEqualTo(this.principal.getName());
		assertThat(authorizedClient.getAccessToken()).isEqualTo(accessTokenResponse.getAccessToken());
	}

	@Test
	public void authorizeWhenClientCredentialsAndTokenNotExpiredThenNotReauthorize() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), TestOAuth2AccessTokens.noScopes());
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withAuthorizedClient(authorizedClient)
				.principal(this.principal)
				.build();
		// @formatter:on
		assertThat(this.authorizedClientProvider.authorize(authorizationContext).block()).isNull();
	}

	// gh-7511
	@Test
	public void authorizeWhenClientCredentialsAndTokenNotExpiredButClockSkewForcesExpiryThenReauthorize() {
		Instant now = Instant.now();
		Instant issuedAt = now.minus(Duration.ofMinutes(60));
		Instant expiresAt = now.minus(Duration.ofMinutes(1));
		OAuth2AccessToken expiresInOneMinAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"access-token-1234", issuedAt, expiresAt);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), expiresInOneMinAccessToken);
		// Shorten the lifespan of the access token by 90 seconds, which will ultimately
		// force it to expire on the client
		this.authorizedClientProvider.setClockSkew(Duration.ofSeconds(90));
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse().build();
		given(this.accessTokenResponseClient.getTokenResponse(any())).willReturn(Mono.just(accessTokenResponse));
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withAuthorizedClient(authorizedClient)
				.principal(this.principal)
				.build();
		// @formatter:on
		OAuth2AuthorizedClient reauthorizedClient = this.authorizedClientProvider.authorize(authorizationContext)
				.block();
		assertThat(reauthorizedClient.getClientRegistration()).isSameAs(this.clientRegistration);
		assertThat(reauthorizedClient.getPrincipalName()).isEqualTo(this.principal.getName());
		assertThat(reauthorizedClient.getAccessToken()).isEqualTo(accessTokenResponse.getAccessToken());
	}

}
