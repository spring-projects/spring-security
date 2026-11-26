/*
 * Copyright 2004-present the original author or authors.
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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.Disposable;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Signal;
import reactor.core.publisher.Sinks;
import reactor.test.StepVerifier;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AccessTokenResponses;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

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

	// gh-17167
	@Test
	public void authorizeWhenConcurrentAndNotAuthorizedThenShareTokenResponse() {
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse().build();
		Sinks.One<OAuth2AccessTokenResponse> tokenResponse = Sinks.one();
		given(this.accessTokenResponseClient.getTokenResponse(any())).willReturn(tokenResponse.asMono());
		Authentication otherPrincipal = new TestingAuthenticationToken("other-principal", "password");
		ClientRegistration otherClientRegistration = TestClientRegistrations.clientCredentials().build();
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(this.clientRegistration)
				.principal(this.principal)
				.build();
		OAuth2AuthorizationContext otherAuthorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(otherClientRegistration)
				.principal(otherPrincipal)
				.build();
		// @formatter:on
		StepVerifier
			.create(Flux.merge(this.authorizedClientProvider.authorize(authorizationContext),
					this.authorizedClientProvider.authorize(otherAuthorizationContext))
				.collectList())
			.expectSubscription()
			.then(() -> {
				verify(this.accessTokenResponseClient).getTokenResponse(any());
				assertThat(tokenResponse.tryEmitValue(accessTokenResponse)).isEqualTo(Sinks.EmitResult.OK);
			})
			.assertNext((authorizedClients) -> assertThat(authorizedClients).hasSize(2)
				.allSatisfy((authorizedClient) -> assertThat(authorizedClient.getAccessToken())
					.isSameAs(accessTokenResponse.getAccessToken()))
				.extracting(OAuth2AuthorizedClient::getPrincipalName)
				.containsExactlyInAnyOrder(this.principal.getName(), otherPrincipal.getName()))
			.verifyComplete();
	}

	// gh-17167
	@Test
	public void authorizeWhenConcurrentAndTokenExpiredThenShareTokenResponse() {
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse()
			.expiresIn(Duration.ofMinutes(5).toSeconds())
			.build();
		Sinks.One<OAuth2AccessTokenResponse> tokenResponse = Sinks.one();
		OAuth2AccessTokenResponse refreshedTokenResponse = OAuth2AccessTokenResponse.withToken("refreshed-token")
			.tokenType(OAuth2AccessToken.TokenType.BEARER)
			.build();
		Sinks.One<OAuth2AccessTokenResponse> refreshedToken = Sinks.one();
		given(this.accessTokenResponseClient.getTokenResponse(any())).willReturn(tokenResponse.asMono(),
				refreshedToken.asMono());
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(this.clientRegistration)
				.principal(this.principal)
				.build();
		// @formatter:on
		StepVerifier.create(this.authorizedClientProvider.authorize(authorizationContext))
			.expectSubscription()
			.then(() -> assertThat(tokenResponse.tryEmitValue(accessTokenResponse)).isEqualTo(Sinks.EmitResult.OK))
			.assertNext((authorizedClient) -> assertThat(authorizedClient.getAccessToken())
				.isSameAs(accessTokenResponse.getAccessToken()))
			.verifyComplete();
		Instant expiresAt = accessTokenResponse.getAccessToken().getExpiresAt().plusSeconds(1);
		this.authorizedClientProvider.setClock(Clock.fixed(expiresAt, ZoneOffset.UTC));
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), accessTokenResponse.getAccessToken());
		// @formatter:off
		OAuth2AuthorizationContext expiredAuthorizationContext = OAuth2AuthorizationContext
				.withAuthorizedClient(authorizedClient)
				.principal(this.principal)
				.build();
		// @formatter:on
		StepVerifier
			.create(Flux.merge(this.authorizedClientProvider.authorize(expiredAuthorizationContext),
					this.authorizedClientProvider.authorize(expiredAuthorizationContext))
				.collectList())
			.expectSubscription()
			.then(() -> {
				verify(this.accessTokenResponseClient, times(2)).getTokenResponse(any());
				assertThat(refreshedToken.tryEmitValue(refreshedTokenResponse)).isEqualTo(Sinks.EmitResult.OK);
			})
			.assertNext((authorizedClients) -> assertThat(authorizedClients).hasSize(2)
				.allSatisfy((reauthorizedClient) -> assertThat(reauthorizedClient.getAccessToken())
					.isSameAs(refreshedTokenResponse.getAccessToken())))
			.verifyComplete();
	}

	// gh-17167
	@Test
	public void authorizeWhenConcurrentAndTokenRequestFailsThenShareErrorAndRetry() {
		OAuth2AuthorizationException error = new OAuth2AuthorizationException(new OAuth2Error("invalid_client"),
				new IllegalStateException("token endpoint failure"));
		Sinks.One<OAuth2AccessTokenResponse> failedTokenResponse = Sinks.one();
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse().build();
		Sinks.One<OAuth2AccessTokenResponse> tokenResponse = Sinks.one();
		given(this.accessTokenResponseClient.getTokenResponse(any())).willReturn(failedTokenResponse.asMono(),
				tokenResponse.asMono());
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(this.clientRegistration)
				.principal(this.principal)
				.build();
		// @formatter:on
		Mono<OAuth2AuthorizedClient> retryingAuthorization = this.authorizedClientProvider
			.authorize(authorizationContext)
			.retry(1);
		StepVerifier
			.create(Flux.merge(retryingAuthorization.materialize(),
					this.authorizedClientProvider.authorize(authorizationContext).materialize()))
			.expectSubscription()
			.then(() -> {
				verify(this.accessTokenResponseClient).getTokenResponse(any());
				assertThat(failedTokenResponse.tryEmitError(error)).isEqualTo(Sinks.EmitResult.OK);
			})
			.then(() -> {
				verify(this.accessTokenResponseClient, times(2)).getTokenResponse(any());
				assertThat(tokenResponse.tryEmitValue(accessTokenResponse)).isEqualTo(Sinks.EmitResult.OK);
			})
			.expectNextMatches((signal) -> isClientAuthorizationException(signal, error))
			.expectNextMatches((signal) -> isSuccessfulAuthorization(signal, accessTokenResponse.getAccessToken()))
			.verifyComplete();
	}

	// gh-17167
	@Test
	public void authorizeWhenConcurrentAndAllCancelledThenSubsequentCallRequestsNewToken() {
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse().build();
		Sinks.One<OAuth2AccessTokenResponse> tokenResponse = Sinks.one();
		// @formatter:off
		OAuth2AccessTokenResponse newTokenResponse = OAuth2AccessTokenResponse
				.withToken("new-access-token")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.build();
		// @formatter:on
		Sinks.One<OAuth2AccessTokenResponse> newTokenResponseSink = Sinks.one();
		given(this.accessTokenResponseClient.getTokenResponse(any())).willReturn(tokenResponse.asMono(),
				newTokenResponseSink.asMono());
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(this.clientRegistration)
				.principal(this.principal)
				.build();
		// @formatter:on
		Disposable firstInFlightRequest = this.authorizedClientProvider.authorize(authorizationContext).subscribe();
		Disposable secondInFlightRequest = this.authorizedClientProvider.authorize(authorizationContext).subscribe();
		verify(this.accessTokenResponseClient).getTokenResponse(any());
		firstInFlightRequest.dispose();
		secondInFlightRequest.dispose();
		assertThat(tokenResponse.tryEmitValue(accessTokenResponse)).isEqualTo(Sinks.EmitResult.OK);
		StepVerifier.create(this.authorizedClientProvider.authorize(authorizationContext))
			.expectSubscription()
			.then(() -> {
				verify(this.accessTokenResponseClient, times(2)).getTokenResponse(any());
				assertThat(newTokenResponseSink.tryEmitValue(newTokenResponse)).isEqualTo(Sinks.EmitResult.OK);
			})
			.assertNext((authorizedClient) -> assertThat(authorizedClient.getAccessToken())
				.isSameAs(newTokenResponse.getAccessToken()))
			.verifyComplete();
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

	private boolean isClientAuthorizationException(Signal<OAuth2AuthorizedClient> signal,
			OAuth2AuthorizationException error) {
		return signal.isOnError() && signal.getThrowable() instanceof ClientAuthorizationException ex
				&& ex.getError().equals(error.getError()) && ex.getCause() == error;
	}

	private boolean isSuccessfulAuthorization(Signal<OAuth2AuthorizedClient> signal, OAuth2AccessToken accessToken) {
		OAuth2AuthorizedClient authorizedClient = signal.get();
		return signal.isOnNext() && authorizedClient != null && authorizedClient.getAccessToken() == accessToken;
	}

}
