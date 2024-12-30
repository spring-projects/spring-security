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

import reactor.core.publisher.Mono;

import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.TokenExchangeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveTokenExchangeTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.util.Assert;

/**
 * An implementation of an {@link ReactiveOAuth2AuthorizedClientProvider} for the
 * {@link AuthorizationGrantType#TOKEN_EXCHANGE token-exchange} grant.
 *
 * @author Steve Riesenberg
 * @since 6.3
 * @see ReactiveOAuth2AuthorizedClientProvider
 * @see WebClientReactiveTokenExchangeTokenResponseClient
 */
public final class TokenExchangeReactiveOAuth2AuthorizedClientProvider
		implements ReactiveOAuth2AuthorizedClientProvider {

	private ReactiveOAuth2AccessTokenResponseClient<TokenExchangeGrantRequest> accessTokenResponseClient = new WebClientReactiveTokenExchangeTokenResponseClient();

	private Function<OAuth2AuthorizationContext, Mono<OAuth2Token>> subjectTokenResolver = this::resolveSubjectToken;

	private Function<OAuth2AuthorizationContext, Mono<OAuth2Token>> actorTokenResolver = (context) -> Mono.empty();

	private Duration clockSkew = Duration.ofSeconds(60);

	private Clock clock = Clock.systemUTC();

	/**
	 * Attempt to authorize (or re-authorize) the
	 * {@link OAuth2AuthorizationContext#getClientRegistration() client} in the provided
	 * {@code context}. Returns an empty {@code Mono} if authorization (or
	 * re-authorization) is not supported, e.g. the client's
	 * {@link ClientRegistration#getAuthorizationGrantType() authorization grant type} is
	 * not {@link AuthorizationGrantType#TOKEN_EXCHANGE token-exchange} OR the
	 * {@link OAuth2AuthorizedClient#getAccessToken() access token} is not expired.
	 * @param context the context that holds authorization-specific state for the client
	 * @return the {@link OAuth2AuthorizedClient} or an empty {@code Mono} if
	 * authorization is not supported
	 */
	@Override
	public Mono<OAuth2AuthorizedClient> authorize(OAuth2AuthorizationContext context) {
		Assert.notNull(context, "context cannot be null");
		ClientRegistration clientRegistration = context.getClientRegistration();
		if (!AuthorizationGrantType.TOKEN_EXCHANGE.equals(clientRegistration.getAuthorizationGrantType())) {
			return Mono.empty();
		}
		OAuth2AuthorizedClient authorizedClient = context.getAuthorizedClient();
		if (authorizedClient != null && !hasTokenExpired(authorizedClient.getAccessToken())) {
			// If client is already authorized but access token is NOT expired than no
			// need for re-authorization
			return Mono.empty();
		}

		return this.subjectTokenResolver.apply(context)
			.flatMap((subjectToken) -> this.actorTokenResolver.apply(context)
				.map((actorToken) -> new TokenExchangeGrantRequest(clientRegistration, subjectToken, actorToken))
				.defaultIfEmpty(new TokenExchangeGrantRequest(clientRegistration, subjectToken, null)))
			.flatMap(this.accessTokenResponseClient::getTokenResponse)
			.onErrorMap(OAuth2AuthorizationException.class,
					(ex) -> new ClientAuthorizationException(ex.getError(), clientRegistration.getRegistrationId(), ex))
			.map((tokenResponse) -> new OAuth2AuthorizedClient(clientRegistration, context.getPrincipal().getName(),
					tokenResponse.getAccessToken(), tokenResponse.getRefreshToken()));
	}

	private Mono<OAuth2Token> resolveSubjectToken(OAuth2AuthorizationContext context) {
		// @formatter:off
		return Mono.just(context)
				.map((ctx) -> ctx.getPrincipal().getPrincipal())
				.filter((principal) -> principal instanceof OAuth2Token)
				.cast(OAuth2Token.class);
		// @formatter:on
	}

	private boolean hasTokenExpired(OAuth2Token token) {
		return this.clock.instant().isAfter(token.getExpiresAt().minus(this.clockSkew));
	}

	/**
	 * Sets the client used when requesting an access token credential at the Token
	 * Endpoint for the {@code token-exchange} grant.
	 * @param accessTokenResponseClient the client used when requesting an access token
	 * credential at the Token Endpoint for the {@code token-exchange} grant
	 */
	public void setAccessTokenResponseClient(
			ReactiveOAuth2AccessTokenResponseClient<TokenExchangeGrantRequest> accessTokenResponseClient) {
		Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
		this.accessTokenResponseClient = accessTokenResponseClient;
	}

	/**
	 * Sets the resolver used for resolving the {@link OAuth2Token subject token}.
	 * @param subjectTokenResolver the resolver used for resolving the {@link OAuth2Token
	 * subject token}
	 */
	public void setSubjectTokenResolver(Function<OAuth2AuthorizationContext, Mono<OAuth2Token>> subjectTokenResolver) {
		Assert.notNull(subjectTokenResolver, "subjectTokenResolver cannot be null");
		this.subjectTokenResolver = subjectTokenResolver;
	}

	/**
	 * Sets the resolver used for resolving the {@link OAuth2Token actor token}.
	 * @param actorTokenResolver the resolver used for resolving the {@link OAuth2Token
	 * actor token}
	 */
	public void setActorTokenResolver(Function<OAuth2AuthorizationContext, Mono<OAuth2Token>> actorTokenResolver) {
		Assert.notNull(actorTokenResolver, "actorTokenResolver cannot be null");
		this.actorTokenResolver = actorTokenResolver;
	}

	/**
	 * Sets the maximum acceptable clock skew, which is used when checking the
	 * {@link OAuth2AuthorizedClient#getAccessToken() access token} expiry. The default is
	 * 60 seconds.
	 *
	 * <p>
	 * An access token is considered expired if
	 * {@code OAuth2AccessToken#getExpiresAt() - clockSkew} is before the current time
	 * {@code clock#instant()}.
	 * @param clockSkew the maximum acceptable clock skew
	 */
	public void setClockSkew(Duration clockSkew) {
		Assert.notNull(clockSkew, "clockSkew cannot be null");
		Assert.isTrue(clockSkew.getSeconds() >= 0, "clockSkew must be >= 0");
		this.clockSkew = clockSkew;
	}

	/**
	 * Sets the {@link Clock} used in {@link Instant#now(Clock)} when checking the access
	 * token expiry.
	 * @param clock the clock
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock cannot be null");
		this.clock = clock;
	}

}
