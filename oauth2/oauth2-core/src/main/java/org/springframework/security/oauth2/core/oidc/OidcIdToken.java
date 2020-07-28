/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.oauth2.core.oidc;

import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.util.Assert;

/**
 * An implementation of an {@link AbstractOAuth2Token} representing an OpenID Connect Core
 * 1.0 ID Token.
 *
 * <p>
 * The {@code OidcIdToken} is a security token that contains &quot;claims&quot; about the
 * authentication of an End-User by an Authorization Server.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AbstractOAuth2Token
 * @see IdTokenClaimAccessor
 * @see StandardClaimAccessor
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-core-1_0.html#IDToken">ID Token</a>
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">Standard
 * Claims</a>
 */
public class OidcIdToken extends AbstractOAuth2Token implements IdTokenClaimAccessor {

	private final Map<String, Object> claims;

	/**
	 * Constructs a {@code OidcIdToken} using the provided parameters.
	 * @param tokenValue the ID Token value
	 * @param issuedAt the time at which the ID Token was issued {@code (iat)}
	 * @param expiresAt the expiration time {@code (exp)} on or after which the ID Token
	 * MUST NOT be accepted
	 * @param claims the claims about the authentication of the End-User
	 */
	public OidcIdToken(String tokenValue, Instant issuedAt, Instant expiresAt, Map<String, Object> claims) {
		super(tokenValue, issuedAt, expiresAt);
		Assert.notEmpty(claims, "claims cannot be empty");
		this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
	}

	@Override
	public Map<String, Object> getClaims() {
		return this.claims;
	}

	/**
	 * Create a {@link Builder} based on the given token value
	 * @param tokenValue the token value to use
	 * @return the {@link Builder} for further configuration
	 * @since 5.3
	 */
	public static Builder withTokenValue(String tokenValue) {
		return new Builder(tokenValue);
	}

	/**
	 * A builder for {@link OidcIdToken}s
	 *
	 * @author Josh Cummings
	 * @since 5.3
	 */
	public static final class Builder {

		private String tokenValue;

		private final Map<String, Object> claims = new LinkedHashMap<>();

		private Builder(String tokenValue) {
			this.tokenValue = tokenValue;
		}

		/**
		 * Use this token value in the resulting {@link OidcIdToken}
		 * @param tokenValue The token value to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder tokenValue(String tokenValue) {
			this.tokenValue = tokenValue;
			return this;
		}

		/**
		 * Use this claim in the resulting {@link OidcIdToken}
		 * @param name The claim name
		 * @param value The claim value
		 * @return the {@link Builder} for further configurations
		 */
		public Builder claim(String name, Object value) {
			this.claims.put(name, value);
			return this;
		}

		/**
		 * Provides access to every {@link #claim(String, Object)} declared so far with
		 * the possibility to add, replace, or remove.
		 * @param claimsConsumer the consumer
		 * @return the {@link Builder} for further configurations
		 */
		public Builder claims(Consumer<Map<String, Object>> claimsConsumer) {
			claimsConsumer.accept(this.claims);
			return this;
		}

		/**
		 * Use this access token hash in the resulting {@link OidcIdToken}
		 * @param accessTokenHash The access token hash to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder accessTokenHash(String accessTokenHash) {
			return claim(IdTokenClaimNames.AT_HASH, accessTokenHash);
		}

		/**
		 * Use this audience in the resulting {@link OidcIdToken}
		 * @param audience The audience(s) to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder audience(Collection<String> audience) {
			return claim(IdTokenClaimNames.AUD, audience);
		}

		/**
		 * Use this authentication {@link Instant} in the resulting {@link OidcIdToken}
		 * @param authenticatedAt The authentication {@link Instant} to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder authTime(Instant authenticatedAt) {
			return claim(IdTokenClaimNames.AUTH_TIME, authenticatedAt);
		}

		/**
		 * Use this authentication context class reference in the resulting
		 * {@link OidcIdToken}
		 * @param authenticationContextClass The authentication context class reference to
		 * use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder authenticationContextClass(String authenticationContextClass) {
			return claim(IdTokenClaimNames.ACR, authenticationContextClass);
		}

		/**
		 * Use these authentication methods in the resulting {@link OidcIdToken}
		 * @param authenticationMethods The authentication methods to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder authenticationMethods(List<String> authenticationMethods) {
			return claim(IdTokenClaimNames.AMR, authenticationMethods);
		}

		/**
		 * Use this authorization code hash in the resulting {@link OidcIdToken}
		 * @param authorizationCodeHash The authorization code hash to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder authorizationCodeHash(String authorizationCodeHash) {
			return claim(IdTokenClaimNames.C_HASH, authorizationCodeHash);
		}

		/**
		 * Use this authorized party in the resulting {@link OidcIdToken}
		 * @param authorizedParty The authorized party to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder authorizedParty(String authorizedParty) {
			return claim(IdTokenClaimNames.AZP, authorizedParty);
		}

		/**
		 * Use this expiration in the resulting {@link OidcIdToken}
		 * @param expiresAt The expiration to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder expiresAt(Instant expiresAt) {
			return this.claim(IdTokenClaimNames.EXP, expiresAt);
		}

		/**
		 * Use this issued-at timestamp in the resulting {@link OidcIdToken}
		 * @param issuedAt The issued-at timestamp to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder issuedAt(Instant issuedAt) {
			return this.claim(IdTokenClaimNames.IAT, issuedAt);
		}

		/**
		 * Use this issuer in the resulting {@link OidcIdToken}
		 * @param issuer The issuer to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder issuer(String issuer) {
			return this.claim(IdTokenClaimNames.ISS, issuer);
		}

		/**
		 * Use this nonce in the resulting {@link OidcIdToken}
		 * @param nonce The nonce to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder nonce(String nonce) {
			return this.claim(IdTokenClaimNames.NONCE, nonce);
		}

		/**
		 * Use this subject in the resulting {@link OidcIdToken}
		 * @param subject The subject to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder subject(String subject) {
			return this.claim(IdTokenClaimNames.SUB, subject);
		}

		/**
		 * Build the {@link OidcIdToken}
		 * @return The constructed {@link OidcIdToken}
		 */
		public OidcIdToken build() {
			Instant iat = toInstant(this.claims.get(IdTokenClaimNames.IAT));
			Instant exp = toInstant(this.claims.get(IdTokenClaimNames.EXP));
			return new OidcIdToken(this.tokenValue, iat, exp, this.claims);
		}

		private Instant toInstant(Object timestamp) {
			if (timestamp != null) {
				Assert.isInstanceOf(Instant.class, timestamp, "timestamps must be of type Instant");
			}
			return (Instant) timestamp;
		}

	}

}
