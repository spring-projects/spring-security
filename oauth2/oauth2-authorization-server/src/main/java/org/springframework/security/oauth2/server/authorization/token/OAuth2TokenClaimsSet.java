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

import java.net.URL;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.util.Assert;

/**
 * A representation of a set of claims that are associated to an {@link OAuth2Token}.
 *
 * @author Joe Grandja
 * @since 0.2.3
 * @see OAuth2TokenClaimAccessor
 * @see OAuth2TokenClaimNames
 * @see OAuth2Token
 */
public final class OAuth2TokenClaimsSet implements OAuth2TokenClaimAccessor {

	private final Map<String, Object> claims;

	private OAuth2TokenClaimsSet(Map<String, Object> claims) {
		this.claims = Collections.unmodifiableMap(new HashMap<>(claims));
	}

	@Override
	public Map<String, Object> getClaims() {
		return this.claims;
	}

	/**
	 * Returns a new {@link Builder}.
	 * @return the {@link Builder}
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * A builder for {@link OAuth2TokenClaimsSet}.
	 */
	public static final class Builder {

		private final Map<String, Object> claims = new HashMap<>();

		private Builder() {
		}

		/**
		 * Sets the issuer {@code (iss)} claim, which identifies the principal that issued
		 * the OAuth 2.0 Token.
		 * @param issuer the issuer identifier
		 * @return the {@link Builder}
		 */
		public Builder issuer(String issuer) {
			return claim(OAuth2TokenClaimNames.ISS, issuer);
		}

		/**
		 * Sets the subject {@code (sub)} claim, which identifies the principal that is
		 * the subject of the OAuth 2.0 Token.
		 * @param subject the subject identifier
		 * @return the {@link Builder}
		 */
		public Builder subject(String subject) {
			return claim(OAuth2TokenClaimNames.SUB, subject);
		}

		/**
		 * Sets the audience {@code (aud)} claim, which identifies the recipient(s) that
		 * the OAuth 2.0 Token is intended for.
		 * @param audience the audience that this OAuth 2.0 Token is intended for
		 * @return the {@link Builder}
		 */
		public Builder audience(List<String> audience) {
			return claim(OAuth2TokenClaimNames.AUD, audience);
		}

		/**
		 * Sets the expiration time {@code (exp)} claim, which identifies the time on or
		 * after which the OAuth 2.0 Token MUST NOT be accepted for processing.
		 * @param expiresAt the time on or after which the OAuth 2.0 Token MUST NOT be
		 * accepted for processing
		 * @return the {@link Builder}
		 */
		public Builder expiresAt(Instant expiresAt) {
			return claim(OAuth2TokenClaimNames.EXP, expiresAt);
		}

		/**
		 * Sets the not before {@code (nbf)} claim, which identifies the time before which
		 * the OAuth 2.0 Token MUST NOT be accepted for processing.
		 * @param notBefore the time before which the OAuth 2.0 Token MUST NOT be accepted
		 * for processing
		 * @return the {@link Builder}
		 */
		public Builder notBefore(Instant notBefore) {
			return claim(OAuth2TokenClaimNames.NBF, notBefore);
		}

		/**
		 * Sets the issued at {@code (iat)} claim, which identifies the time at which the
		 * OAuth 2.0 Token was issued.
		 * @param issuedAt the time at which the OAuth 2.0 Token was issued
		 * @return the {@link Builder}
		 */
		public Builder issuedAt(Instant issuedAt) {
			return claim(OAuth2TokenClaimNames.IAT, issuedAt);
		}

		/**
		 * Sets the ID {@code (jti)} claim, which provides a unique identifier for the
		 * OAuth 2.0 Token.
		 * @param jti the unique identifier for the OAuth 2.0 Token
		 * @return the {@link Builder}
		 */
		public Builder id(String jti) {
			return claim(OAuth2TokenClaimNames.JTI, jti);
		}

		/**
		 * Sets the claim.
		 * @param name the claim name
		 * @param value the claim value
		 * @return the {@link Builder}
		 */
		public Builder claim(String name, Object value) {
			Assert.hasText(name, "name cannot be empty");
			Assert.notNull(value, "value cannot be null");
			this.claims.put(name, value);
			return this;
		}

		/**
		 * A {@code Consumer} to be provided access to the claims allowing the ability to
		 * add, replace, or remove.
		 * @param claimsConsumer a {@code Consumer} of the claims
		 * @return the {@link Builder}
		 */
		public Builder claims(Consumer<Map<String, Object>> claimsConsumer) {
			claimsConsumer.accept(this.claims);
			return this;
		}

		/**
		 * Builds a new {@link OAuth2TokenClaimsSet}.
		 * @return a {@link OAuth2TokenClaimsSet}
		 */
		public OAuth2TokenClaimsSet build() {
			Assert.notEmpty(this.claims, "claims cannot be empty");

			// The value of the 'iss' claim is a String or URL (StringOrURI).
			// Attempt to convert to URL.
			Object issuer = this.claims.get(OAuth2TokenClaimNames.ISS);
			if (issuer != null) {
				URL convertedValue = ClaimConversionService.getSharedInstance().convert(issuer, URL.class);
				if (convertedValue != null) {
					this.claims.put(OAuth2TokenClaimNames.ISS, convertedValue);
				}
			}

			return new OAuth2TokenClaimsSet(this.claims);
		}

	}

}
