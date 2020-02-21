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

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.client.endpoint.DefaultRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.Assert;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * An implementation of an {@link OAuth2AuthorizedClientProvider}
 * for the {@link AuthorizationGrantType#REFRESH_TOKEN refresh_token} grant.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see OAuth2AuthorizedClientProvider
 * @see DefaultRefreshTokenTokenResponseClient
 */
public final class RefreshTokenOAuth2AuthorizedClientProvider implements OAuth2AuthorizedClientProvider {
	private OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> accessTokenResponseClient =
			new DefaultRefreshTokenTokenResponseClient();
	private Duration clockSkew = Duration.ofSeconds(60);
	private Clock clock = Clock.systemUTC();

	/**
	 * Attempt to re-authorize the {@link OAuth2AuthorizationContext#getClientRegistration() client} in the provided {@code context}.
	 * Returns {@code null} if re-authorization is not supported,
	 * e.g. the client is not authorized OR the {@link OAuth2AuthorizedClient#getRefreshToken() refresh token}
	 * is not available for the authorized client OR the {@link OAuth2AuthorizedClient#getAccessToken() access token} is not expired.
	 *
	 * <p>
	 * The following {@link OAuth2AuthorizationContext#getAttributes() context attributes} are supported:
	 * <ol>
	 *  <li>{@link OAuth2AuthorizationContext#REQUEST_SCOPE_ATTRIBUTE_NAME} (optional) - a {@code String[]} of scope(s)
	 *  	to be requested by the {@link OAuth2AuthorizationContext#getClientRegistration() client}</li>
	 * </ol>
	 *
	 * @param context the context that holds authorization-specific state for the client
	 * @return the {@link OAuth2AuthorizedClient} or {@code null} if re-authorization is not supported
	 */
	@Override
	@Nullable
	public OAuth2AuthorizedClient authorize(OAuth2AuthorizationContext context) {
		Assert.notNull(context, "context cannot be null");

		OAuth2AuthorizedClient authorizedClient = context.getAuthorizedClient();
		if (authorizedClient == null ||
				authorizedClient.getRefreshToken() == null ||
				!hasTokenExpired(authorizedClient.getAccessToken())) {
			return null;
		}

		Object requestScope = context.getAttribute(OAuth2AuthorizationContext.REQUEST_SCOPE_ATTRIBUTE_NAME);
		Set<String> scopes = Collections.emptySet();
		if (requestScope != null) {
			Assert.isInstanceOf(String[].class, requestScope,
					"The context attribute must be of type String[] '" + OAuth2AuthorizationContext.REQUEST_SCOPE_ATTRIBUTE_NAME + "'");
			scopes = new HashSet<>(Arrays.asList((String[]) requestScope));
		}

		OAuth2RefreshTokenGrantRequest refreshTokenGrantRequest = new OAuth2RefreshTokenGrantRequest(
				authorizedClient.getClientRegistration(), authorizedClient.getAccessToken(),
				authorizedClient.getRefreshToken(), scopes);

		OAuth2AccessTokenResponse tokenResponse;
		try {
			tokenResponse = this.accessTokenResponseClient.getTokenResponse(refreshTokenGrantRequest);
		} catch (OAuth2AuthorizationException ex) {
			throw new ClientAuthorizationException(ex.getError(), authorizedClient.getClientRegistration().getRegistrationId(), ex);
		}

		return new OAuth2AuthorizedClient(context.getAuthorizedClient().getClientRegistration(),
				context.getPrincipal().getName(), tokenResponse.getAccessToken(), tokenResponse.getRefreshToken());
	}

	private boolean hasTokenExpired(AbstractOAuth2Token token) {
		return this.clock.instant().isAfter(token.getExpiresAt().minus(this.clockSkew));
	}

	/**
	 * Sets the client used when requesting an access token credential at the Token Endpoint for the {@code refresh_token} grant.
	 *
	 * @param accessTokenResponseClient the client used when requesting an access token credential at the Token Endpoint for the {@code refresh_token} grant
	 */
	public void setAccessTokenResponseClient(OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> accessTokenResponseClient) {
		Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
		this.accessTokenResponseClient = accessTokenResponseClient;
	}

	/**
	 * Sets the maximum acceptable clock skew, which is used when checking the
	 * {@link OAuth2AuthorizedClient#getAccessToken() access token} expiry. The default is 60 seconds.
	 * An access token is considered expired if it's before {@code Instant.now(this.clock) - clockSkew}.
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
