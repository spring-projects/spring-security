/*
 * Copyright 2002-2024 the original author or authors.
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
import java.util.function.Function;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.TokenExchangeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AccessTokenResponses;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link TokenExchangeReactiveOAuth2AuthorizedClientProvider}.
 *
 * @author Steve Riesenberg
 */
public class TokenExchangeReactiveOAuth2AuthorizedClientProviderTests {

	private TokenExchangeReactiveOAuth2AuthorizedClientProvider authorizedClientProvider;

	private ReactiveOAuth2AccessTokenResponseClient<TokenExchangeGrantRequest> accessTokenResponseClient;

	private ClientRegistration clientRegistration;

	private OAuth2Token subjectToken;

	private OAuth2Token actorToken;

	private Authentication principal;

	@BeforeEach
	public void setUp() {
		this.authorizedClientProvider = new TokenExchangeReactiveOAuth2AuthorizedClientProvider();
		this.accessTokenResponseClient = mock(ReactiveOAuth2AccessTokenResponseClient.class);
		this.authorizedClientProvider.setAccessTokenResponseClient(this.accessTokenResponseClient);
		// @formatter:off
		this.clientRegistration = ClientRegistration.withRegistrationId("token-exchange")
				.clientId("client-id")
				.clientSecret("client-secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
				.scope("read", "write")
				.tokenUri("https://example.com/oauth2/token")
				.build();
		// @formatter:on
		this.subjectToken = TestOAuth2AccessTokens.scopes("read", "write");
		this.actorToken = TestOAuth2AccessTokens.noScopes();
		this.principal = new TestingAuthenticationToken(this.subjectToken, this.subjectToken);
	}

	@Test
	public void setAccessTokenResponseClientWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizedClientProvider.setAccessTokenResponseClient(null))
				.withMessage("accessTokenResponseClient cannot be null");
		// @formatter:on
	}

	@Test
	public void setSubjectTokenResolverWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizedClientProvider.setSubjectTokenResolver(null))
				.withMessage("subjectTokenResolver cannot be null");
		// @formatter:on
	}

	@Test
	public void setActorTokenResolverWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizedClientProvider.setActorTokenResolver(null))
				.withMessage("actorTokenResolver cannot be null");
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
	public void authorizeWhenNotTokenExchangeThenUnableToAuthorize() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientCredentials().build();
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(clientRegistration)
				.principal(this.principal)
				.build();
		// @formatter:on
		assertThat(this.authorizedClientProvider.authorize(authorizationContext).block()).isNull();
		verifyNoInteractions(this.accessTokenResponseClient);
	}

	@Test
	public void authorizeWhenTokenExchangeAndTokenNotExpiredThenNotReauthorized() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), TestOAuth2AccessTokens.scopes("read", "write"));
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withAuthorizedClient(authorizedClient)
				.principal(this.principal)
				.build();
		// @formatter:on
		assertThat(this.authorizedClientProvider.authorize(authorizationContext).block()).isNull();
		verifyNoInteractions(this.accessTokenResponseClient);
	}

	@Test
	public void authorizeWhenInvalidRequestThenThrowClientAuthorizationException() {
		given(this.accessTokenResponseClient.getTokenResponse(any(TokenExchangeGrantRequest.class))).willReturn(
				Mono.error(new OAuth2AuthorizationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST))));
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(this.clientRegistration)
				.principal(this.principal)
				.build();
		// @formatter:on

		// @formatter:off
		assertThatExceptionOfType(ClientAuthorizationException.class)
				.isThrownBy(() -> this.authorizedClientProvider.authorize(authorizationContext).block())
				.satisfies((ex) -> assertThat(ex.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST))
				.withMessageContaining("[invalid_request]");
		// @formatter:on
		ArgumentCaptor<TokenExchangeGrantRequest> grantRequestCaptor = ArgumentCaptor
			.forClass(TokenExchangeGrantRequest.class);
		verify(this.accessTokenResponseClient).getTokenResponse(grantRequestCaptor.capture());
		TokenExchangeGrantRequest grantRequest = grantRequestCaptor.getValue();
		assertThat(grantRequest.getSubjectToken()).isEqualTo(this.subjectToken);
		assertThat(grantRequest.getActorToken()).isNull();
	}

	@Test
	public void authorizeWhenTokenExchangeAndTokenExpiredThenReauthorized() {
		Instant now = Instant.now();
		Instant issuedAt = now.minus(Duration.ofMinutes(60));
		Instant expiresAt = now.minus(Duration.ofMinutes(30));
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token-1234",
				issuedAt, expiresAt);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), accessToken);
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse()
			.refreshToken("refresh")
			.build();
		given(this.accessTokenResponseClient.getTokenResponse(any(TokenExchangeGrantRequest.class)))
			.willReturn(Mono.just(accessTokenResponse));
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withAuthorizedClient(authorizedClient)
				.principal(this.principal)
				.build();
		// @formatter:on
		OAuth2AuthorizedClient reauthorizedClient = this.authorizedClientProvider.authorize(authorizationContext)
			.block();
		assertThat(reauthorizedClient).isNotNull();
		assertThat(reauthorizedClient).isNotEqualTo(authorizedClient);
		assertThat(reauthorizedClient.getClientRegistration()).isSameAs(this.clientRegistration);
		assertThat(reauthorizedClient.getPrincipalName()).isEqualTo(this.principal.getName());
		assertThat(reauthorizedClient.getAccessToken()).isEqualTo(accessTokenResponse.getAccessToken());
		assertThat(reauthorizedClient.getRefreshToken()).isEqualTo(accessTokenResponse.getRefreshToken());
		ArgumentCaptor<TokenExchangeGrantRequest> grantRequestCaptor = ArgumentCaptor
			.forClass(TokenExchangeGrantRequest.class);
		verify(this.accessTokenResponseClient).getTokenResponse(grantRequestCaptor.capture());
		TokenExchangeGrantRequest grantRequest = grantRequestCaptor.getValue();
		assertThat(grantRequest.getSubjectToken()).isEqualTo(this.subjectToken);
		assertThat(grantRequest.getActorToken()).isNull();
	}

	@Test
	public void authorizeWhenTokenExchangeAndTokenNotExpiredButClockSkewForcesExpiryThenReauthorized() {
		Instant now = Instant.now();
		Instant issuedAt = now.minus(Duration.ofMinutes(60));
		Instant expiresAt = now.plus(Duration.ofMinutes(1));
		OAuth2AccessToken expiresInOneMinAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"access-token-1234", issuedAt, expiresAt);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), expiresInOneMinAccessToken);
		// Shorten the lifespan of the access token by 90 seconds, which will ultimately
		// force it to expire on the client
		this.authorizedClientProvider.setClockSkew(Duration.ofSeconds(90));
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse()
			.refreshToken("refresh")
			.build();
		given(this.accessTokenResponseClient.getTokenResponse(any(TokenExchangeGrantRequest.class)))
			.willReturn(Mono.just(accessTokenResponse));
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withAuthorizedClient(authorizedClient)
				.principal(this.principal)
				.build();
		// @formatter:on
		OAuth2AuthorizedClient reauthorizedClient = this.authorizedClientProvider.authorize(authorizationContext)
			.block();
		assertThat(reauthorizedClient).isNotNull();
		assertThat(reauthorizedClient).isNotEqualTo(authorizedClient);
		assertThat(reauthorizedClient.getClientRegistration()).isSameAs(this.clientRegistration);
		assertThat(reauthorizedClient.getPrincipalName()).isEqualTo(this.principal.getName());
		assertThat(reauthorizedClient.getAccessToken()).isEqualTo(accessTokenResponse.getAccessToken());
		assertThat(reauthorizedClient.getRefreshToken()).isEqualTo(accessTokenResponse.getRefreshToken());
		ArgumentCaptor<TokenExchangeGrantRequest> grantRequestCaptor = ArgumentCaptor
			.forClass(TokenExchangeGrantRequest.class);
		verify(this.accessTokenResponseClient).getTokenResponse(grantRequestCaptor.capture());
		TokenExchangeGrantRequest grantRequest = grantRequestCaptor.getValue();
		assertThat(grantRequest.getSubjectToken()).isEqualTo(this.subjectToken);
		assertThat(grantRequest.getActorToken()).isNull();
	}

	@Test
	public void authorizeWhenTokenExchangeAndNotAuthorizedAndSubjectTokenDoesNotResolveThenUnableToAuthorize() {
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(this.clientRegistration)
				.principal(new TestingAuthenticationToken("user", "password"))
				.build();
		// @formatter:on
		assertThat(this.authorizedClientProvider.authorize(authorizationContext).block()).isNull();
		verifyNoInteractions(this.accessTokenResponseClient);
	}

	@Test
	public void authorizeWhenTokenExchangeAndNotAuthorizedAndSubjectTokenResolvesThenAuthorized() {
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse()
			.refreshToken("refresh")
			.build();
		given(this.accessTokenResponseClient.getTokenResponse(any(TokenExchangeGrantRequest.class)))
			.willReturn(Mono.just(accessTokenResponse));
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(this.clientRegistration)
				.principal(this.principal)
				.build();
		// @formatter:on
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientProvider.authorize(authorizationContext).block();
		assertThat(authorizedClient).isNotNull();
		assertThat(authorizedClient.getClientRegistration()).isSameAs(this.clientRegistration);
		assertThat(authorizedClient.getPrincipalName()).isEqualTo(this.principal.getName());
		assertThat(authorizedClient.getAccessToken()).isEqualTo(accessTokenResponse.getAccessToken());
		assertThat(authorizedClient.getRefreshToken()).isEqualTo(accessTokenResponse.getRefreshToken());
		ArgumentCaptor<TokenExchangeGrantRequest> grantRequestCaptor = ArgumentCaptor
			.forClass(TokenExchangeGrantRequest.class);
		verify(this.accessTokenResponseClient).getTokenResponse(grantRequestCaptor.capture());
		TokenExchangeGrantRequest grantRequest = grantRequestCaptor.getValue();
		assertThat(grantRequest.getSubjectToken()).isEqualTo(this.subjectToken);
		assertThat(grantRequest.getActorToken()).isNull();
	}

	@Test
	public void authorizeWhenCustomSubjectTokenResolverSetThenCalled() {
		Function<OAuth2AuthorizationContext, Mono<OAuth2Token>> subjectTokenResolver = mock(Function.class);
		given(subjectTokenResolver.apply(any(OAuth2AuthorizationContext.class)))
			.willReturn(Mono.just(this.subjectToken));
		this.authorizedClientProvider.setSubjectTokenResolver(subjectTokenResolver);
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse()
			.refreshToken("refresh")
			.build();
		given(this.accessTokenResponseClient.getTokenResponse(any(TokenExchangeGrantRequest.class)))
			.willReturn(Mono.just(accessTokenResponse));
		TestingAuthenticationToken principal = new TestingAuthenticationToken("user", "password");
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(this.clientRegistration)
				.principal(principal)
				.build();
		// @formatter:on
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientProvider.authorize(authorizationContext).block();
		assertThat(authorizedClient).isNotNull();
		assertThat(authorizedClient.getClientRegistration()).isSameAs(this.clientRegistration);
		assertThat(authorizedClient.getPrincipalName()).isEqualTo(principal.getName());
		assertThat(authorizedClient.getAccessToken()).isEqualTo(accessTokenResponse.getAccessToken());
		assertThat(authorizedClient.getRefreshToken()).isEqualTo(accessTokenResponse.getRefreshToken());
		verify(subjectTokenResolver).apply(authorizationContext);
		ArgumentCaptor<TokenExchangeGrantRequest> grantRequestCaptor = ArgumentCaptor
			.forClass(TokenExchangeGrantRequest.class);
		verify(this.accessTokenResponseClient).getTokenResponse(grantRequestCaptor.capture());
		TokenExchangeGrantRequest grantRequest = grantRequestCaptor.getValue();
		assertThat(grantRequest.getSubjectToken()).isEqualTo(this.subjectToken);
		assertThat(grantRequest.getActorToken()).isNull();
	}

	@Test
	public void authorizeWhenCustomActorTokenResolverSetThenCalled() {
		Function<OAuth2AuthorizationContext, Mono<OAuth2Token>> actorTokenResolver = mock(Function.class);
		given(actorTokenResolver.apply(any(OAuth2AuthorizationContext.class))).willReturn(Mono.just(this.actorToken));
		this.authorizedClientProvider.setActorTokenResolver(actorTokenResolver);
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse()
			.refreshToken("refresh")
			.build();
		given(this.accessTokenResponseClient.getTokenResponse(any(TokenExchangeGrantRequest.class)))
			.willReturn(Mono.just(accessTokenResponse));
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(this.clientRegistration)
				.principal(this.principal)
				.build();
		// @formatter:on
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientProvider.authorize(authorizationContext).block();
		assertThat(authorizedClient).isNotNull();
		assertThat(authorizedClient.getClientRegistration()).isSameAs(this.clientRegistration);
		assertThat(authorizedClient.getPrincipalName()).isEqualTo(this.principal.getName());
		assertThat(authorizedClient.getAccessToken()).isEqualTo(accessTokenResponse.getAccessToken());
		assertThat(authorizedClient.getRefreshToken()).isEqualTo(accessTokenResponse.getRefreshToken());
		verify(actorTokenResolver).apply(authorizationContext);
		ArgumentCaptor<TokenExchangeGrantRequest> grantRequestCaptor = ArgumentCaptor
			.forClass(TokenExchangeGrantRequest.class);
		verify(this.accessTokenResponseClient).getTokenResponse(grantRequestCaptor.capture());
		TokenExchangeGrantRequest grantRequest = grantRequestCaptor.getValue();
		assertThat(grantRequest.getSubjectToken()).isEqualTo(this.subjectToken);
		assertThat(grantRequest.getActorToken()).isEqualTo(this.actorToken);
	}

	@Test
	public void authorizeWhenClockSetThenCalled() {
		Clock clock = mock(Clock.class);
		given(clock.instant()).willReturn(Instant.now());
		this.authorizedClientProvider.setClock(clock);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), TestOAuth2AccessTokens.noScopes());
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withAuthorizedClient(authorizedClient)
				.principal(this.principal)
				.build();
		// @formatter:on
		assertThat(this.authorizedClientProvider.authorize(authorizationContext).block()).isNull();
		verify(clock).instant();
	}

}
