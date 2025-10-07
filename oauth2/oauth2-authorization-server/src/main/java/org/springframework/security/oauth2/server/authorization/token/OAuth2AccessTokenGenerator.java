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

package org.springframework.security.oauth2.server.authorization.token;

import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.springframework.lang.Nullable;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * An {@link OAuth2TokenGenerator} that generates a {@link OAuth2TokenFormat#REFERENCE
 * "reference"} (opaque) {@link OAuth2AccessToken}.
 *
 * @author Joe Grandja
 * @since 7.0
 * @see OAuth2TokenGenerator
 * @see OAuth2AccessToken
 * @see OAuth2TokenCustomizer
 * @see OAuth2TokenClaimsContext
 * @see OAuth2TokenClaimsSet
 */
public final class OAuth2AccessTokenGenerator implements OAuth2TokenGenerator<OAuth2AccessToken> {

	private final StringKeyGenerator accessTokenGenerator = new Base64StringKeyGenerator(
			Base64.getUrlEncoder().withoutPadding(), 96);

	private OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer;

	private Clock clock = Clock.systemUTC();

	@Nullable
	@Override
	public OAuth2AccessToken generate(OAuth2TokenContext context) {
		// @formatter:off
		if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType()) ||
				!OAuth2TokenFormat.REFERENCE.equals(context.getRegisteredClient().getTokenSettings().getAccessTokenFormat())) {
			return null;
		}
		// @formatter:on

		String issuer = null;
		if (context.getAuthorizationServerContext() != null) {
			issuer = context.getAuthorizationServerContext().getIssuer();
		}
		RegisteredClient registeredClient = context.getRegisteredClient();

		Instant issuedAt = this.clock.instant();
		Instant expiresAt = issuedAt.plus(registeredClient.getTokenSettings().getAccessTokenTimeToLive());

		// @formatter:off
		OAuth2TokenClaimsSet.Builder claimsBuilder = OAuth2TokenClaimsSet.builder();
		if (StringUtils.hasText(issuer)) {
			claimsBuilder.issuer(issuer);
		}
		claimsBuilder
				.subject(context.getPrincipal().getName())
				.audience(Collections.singletonList(registeredClient.getClientId()))
				.issuedAt(issuedAt)
				.expiresAt(expiresAt)
				.notBefore(issuedAt)
				.id(UUID.randomUUID().toString());
		if (!CollectionUtils.isEmpty(context.getAuthorizedScopes())) {
			claimsBuilder.claim(OAuth2ParameterNames.SCOPE, context.getAuthorizedScopes());
		}
		// @formatter:on

		if (this.accessTokenCustomizer != null) {
			// @formatter:off
			OAuth2TokenClaimsContext.Builder accessTokenContextBuilder = OAuth2TokenClaimsContext.with(claimsBuilder)
					.registeredClient(context.getRegisteredClient())
					.principal(context.getPrincipal())
					.authorizationServerContext(context.getAuthorizationServerContext())
					.authorizedScopes(context.getAuthorizedScopes())
					.tokenType(context.getTokenType())
					.authorizationGrantType(context.getAuthorizationGrantType());
			if (context.getAuthorization() != null) {
				accessTokenContextBuilder.authorization(context.getAuthorization());
			}
			if (context.getAuthorizationGrant() != null) {
				accessTokenContextBuilder.authorizationGrant(context.getAuthorizationGrant());
			}
			if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
				Jwt dPoPProofJwt = context.get(OAuth2TokenContext.DPOP_PROOF_KEY);
				if (dPoPProofJwt != null) {
					accessTokenContextBuilder.put(OAuth2TokenContext.DPOP_PROOF_KEY, dPoPProofJwt);
				}
			}
			// @formatter:on

			OAuth2TokenClaimsContext accessTokenContext = accessTokenContextBuilder.build();
			this.accessTokenCustomizer.customize(accessTokenContext);
		}

		OAuth2TokenClaimsSet accessTokenClaimsSet = claimsBuilder.build();

		OAuth2AccessToken accessToken = new OAuth2AccessTokenClaims(OAuth2AccessToken.TokenType.BEARER,
				this.accessTokenGenerator.generateKey(), accessTokenClaimsSet.getIssuedAt(),
				accessTokenClaimsSet.getExpiresAt(), context.getAuthorizedScopes(), accessTokenClaimsSet.getClaims());

		return accessToken;
	}

	/**
	 * Sets the {@link OAuth2TokenCustomizer} that customizes the
	 * {@link OAuth2TokenClaimsContext#getClaims() claims} for the
	 * {@link OAuth2AccessToken}.
	 * @param accessTokenCustomizer the {@link OAuth2TokenCustomizer} that customizes the
	 * claims for the {@code OAuth2AccessToken}
	 */
	public void setAccessTokenCustomizer(OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer) {
		Assert.notNull(accessTokenCustomizer, "accessTokenCustomizer cannot be null");
		this.accessTokenCustomizer = accessTokenCustomizer;
	}

	/**
	 * Sets the {@link Clock} used when obtaining the current instant via
	 * {@link Clock#instant()}.
	 * @param clock the {@link Clock} used when obtaining the current instant via
	 * {@link Clock#instant()}
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock cannot be null");
		this.clock = clock;
	}

	private static final class OAuth2AccessTokenClaims extends OAuth2AccessToken implements ClaimAccessor {

		private final Map<String, Object> claims;

		private OAuth2AccessTokenClaims(TokenType tokenType, String tokenValue, Instant issuedAt, Instant expiresAt,
				Set<String> scopes, Map<String, Object> claims) {
			super(tokenType, tokenValue, issuedAt, expiresAt, scopes);
			this.claims = claims;
		}

		@Override
		public Map<String, Object> getClaims() {
			return this.claims;
		}

	}

}
