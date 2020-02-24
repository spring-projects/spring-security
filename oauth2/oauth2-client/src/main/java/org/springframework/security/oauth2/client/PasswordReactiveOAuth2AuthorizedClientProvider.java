/*
 * Copyright 2002-2020 the original author or authors.
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

import org.springframework.security.oauth2.client.endpoint.OAuth2PasswordGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.WebClientReactivePasswordTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * An implementation of a {@link ReactiveOAuth2AuthorizedClientProvider}
 * for the {@link AuthorizationGrantType#PASSWORD password} grant.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see ReactiveOAuth2AuthorizedClientProvider
 * @see WebClientReactivePasswordTokenResponseClient
 */
public final class PasswordReactiveOAuth2AuthorizedClientProvider implements ReactiveOAuth2AuthorizedClientProvider {
	private ReactiveOAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> accessTokenResponseClient =
			new WebClientReactivePasswordTokenResponseClient();
	private Duration clockSkew = Duration.ofSeconds(60);
	private Clock clock = Clock.systemUTC();

	/**
	 * Attempt to authorize (or re-authorize) the {@link OAuth2AuthorizationContext#getClientRegistration() client} in the provided {@code context}.
	 * Returns an empty {@code Mono} if authorization (or re-authorization) is not supported,
	 * e.g. the client's {@link ClientRegistration#getAuthorizationGrantType() authorization grant type}
	 * is not {@link AuthorizationGrantType#PASSWORD password} OR
	 * the {@link OAuth2AuthorizationContext#USERNAME_ATTRIBUTE_NAME username} and/or
	 * {@link OAuth2AuthorizationContext#PASSWORD_ATTRIBUTE_NAME password} attributes
	 * are not available in the provided {@code context} OR
	 * the {@link OAuth2AuthorizedClient#getAccessToken() access token} is not expired.
	 *
	 * <p>
	 * The following {@link OAuth2AuthorizationContext#getAttributes() context attributes} are supported:
	 * <ol>
	 *  <li>{@link OAuth2AuthorizationContext#USERNAME_ATTRIBUTE_NAME} (required) - a {@code String} value for the resource owner's username</li>
	 *  <li>{@link OAuth2AuthorizationContext#PASSWORD_ATTRIBUTE_NAME} (required) - a {@code String} value for the resource owner's password</li>
	 * </ol>
	 *
	 * @param context the context that holds authorization-specific state for the client
	 * @return the {@link OAuth2AuthorizedClient} or an empty {@code Mono} if authorization (or re-authorization) is not supported
	 */
	@Override
	public Mono<OAuth2AuthorizedClient> authorize(OAuth2AuthorizationContext context) {
		Assert.notNull(context, "context cannot be null");

		ClientRegistration clientRegistration = context.getClientRegistration();
		OAuth2AuthorizedClient authorizedClient = context.getAuthorizedClient();

		if (!AuthorizationGrantType.PASSWORD.equals(clientRegistration.getAuthorizationGrantType())) {
			return Mono.empty();
		}

		String username = context.getAttribute(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME);
		String password = context.getAttribute(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME);
		if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
			return Mono.empty();
		}

		if (authorizedClient != null && !hasTokenExpired(authorizedClient.getAccessToken())) {
			// If client is already authorized and access token is NOT expired than no need for re-authorization
			return Mono.empty();
		}

		if (authorizedClient != null && hasTokenExpired(authorizedClient.getAccessToken()) && authorizedClient.getRefreshToken() != null) {
			// If client is already authorized and access token is expired and a refresh token is available,
			// than return and allow RefreshTokenReactiveOAuth2AuthorizedClientProvider to handle the refresh
			return Mono.empty();
		}

		OAuth2PasswordGrantRequest passwordGrantRequest =
				new OAuth2PasswordGrantRequest(clientRegistration, username, password);

		return Mono.just(passwordGrantRequest)
				.flatMap(this.accessTokenResponseClient::getTokenResponse)
				.onErrorMap(OAuth2AuthorizationException.class,
						e -> new ClientAuthorizationException(e.getError(), clientRegistration.getRegistrationId(), e))
				.map(tokenResponse -> new OAuth2AuthorizedClient(clientRegistration, context.getPrincipal().getName(),
						tokenResponse.getAccessToken(), tokenResponse.getRefreshToken()));
	}

	private boolean hasTokenExpired(AbstractOAuth2Token token) {
		return this.clock.instant().isAfter(token.getExpiresAt().minus(this.clockSkew));
	}

	/**
	 * Sets the client used when requesting an access token credential at the Token Endpoint for the {@code password} grant.
	 *
	 * @param accessTokenResponseClient the client used when requesting an access token credential at the Token Endpoint for the {@code password} grant
	 */
	public void setAccessTokenResponseClient(ReactiveOAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> accessTokenResponseClient) {
		Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
		this.accessTokenResponseClient = accessTokenResponseClient;
	}

	/**
	 * Sets the maximum acceptable clock skew, which is used when checking the
	 * {@link OAuth2AuthorizedClient#getAccessToken() access token} expiry. The default is 60 seconds.
	 *
	 * <p>
	 * An access token is considered expired if {@code OAuth2AccessToken#getExpiresAt() - clockSkew}
	 * is before the current time {@code clock#instant()}.
	 *
	 * @param clockSkew the maximum acceptable clock skew
	 */
	public void setClockSkew(Duration clockSkew) {
		Assert.notNull(clockSkew, "clockSkew cannot be null");
		Assert.isTrue(clockSkew.getSeconds() >= 0, "clockSkew must be >= 0");
		this.clockSkew = clockSkew;
	}

	/**
	 * Sets the {@link Clock} used in {@link Instant#now(Clock)} when checking the access token expiry.
	 *
	 * @param clock the clock
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock cannot be null");
		this.clock = clock;
	}
}
