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
package org.springframework.security.oauth2.jwt;

import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.util.Assert;

import static org.springframework.security.oauth2.jwt.JwtClaimNames.AUD;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.EXP;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.IAT;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.ISS;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.JTI;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.NBF;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.SUB;

/**
 * An implementation of an {@link AbstractOAuth2Token} representing a JSON Web Token
 * (JWT).
 *
 * <p>
 * JWTs represent a set of &quot;claims&quot; as a JSON object that may be encoded in a
 * JSON Web Signature (JWS) and/or JSON Web Encryption (JWE) structure. The JSON object,
 * also known as the JWT Claims Set, consists of one or more claim name/value pairs. The
 * claim name is a {@code String} and the claim value is an arbitrary JSON object.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AbstractOAuth2Token
 * @see JwtClaimAccessor
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JSON Web Token
 * (JWT)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515">JSON Web Signature
 * (JWS)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7516">JSON Web Encryption
 * (JWE)</a>
 */
public class Jwt extends AbstractOAuth2Token implements JwtClaimAccessor {

	private final Map<String, Object> headers;

	private final Map<String, Object> claims;

	/**
	 * Constructs a {@code Jwt} using the provided parameters.
	 * @param tokenValue the token value
	 * @param issuedAt the time at which the JWT was issued
	 * @param expiresAt the expiration time on or after which the JWT MUST NOT be accepted
	 * @param headers the JOSE header(s)
	 * @param claims the JWT Claims Set
	 *
	 */
	public Jwt(String tokenValue, Instant issuedAt, Instant expiresAt, Map<String, Object> headers,
			Map<String, Object> claims) {
		super(tokenValue, issuedAt, expiresAt);
		Assert.notEmpty(headers, "headers cannot be empty");
		Assert.notEmpty(claims, "claims cannot be empty");
		this.headers = Collections.unmodifiableMap(new LinkedHashMap<>(headers));
		this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
	}

	/**
	 * Returns the JOSE header(s).
	 * @return a {@code Map} of the JOSE header(s)
	 */
	public Map<String, Object> getHeaders() {
		return this.headers;
	}

	/**
	 * Returns the JWT Claims Set.
	 * @return a {@code Map} of the JWT Claims Set
	 */
	@Override
	public Map<String, Object> getClaims() {
		return this.claims;
	}

	/**
	 * Return a {@link Jwt.Builder}
	 * @return A {@link Jwt.Builder}
	 */
	public static Builder withTokenValue(String tokenValue) {
		return new Builder(tokenValue);
	}

	/**
	 * Helps configure a {@link Jwt}
	 *
	 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
	 * @author Josh Cummings
	 * @since 5.2
	 */
	public static final class Builder {

		private String tokenValue;

		private final Map<String, Object> claims = new LinkedHashMap<>();

		private final Map<String, Object> headers = new LinkedHashMap<>();

		private Builder(String tokenValue) {
			this.tokenValue = tokenValue;
		}

		/**
		 * Use this token value in the resulting {@link Jwt}
		 * @param tokenValue The token value to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder tokenValue(String tokenValue) {
			this.tokenValue = tokenValue;
			return this;
		}

		/**
		 * Use this claim in the resulting {@link Jwt}
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
		 * Use this header in the resulting {@link Jwt}
		 * @param name The header name
		 * @param value The header value
		 * @return the {@link Builder} for further configurations
		 */
		public Builder header(String name, Object value) {
			this.headers.put(name, value);
			return this;
		}

		/**
		 * Provides access to every {@link #header(String, Object)} declared so far with
		 * the possibility to add, replace, or remove.
		 * @param headersConsumer the consumer
		 * @return the {@link Builder} for further configurations
		 */
		public Builder headers(Consumer<Map<String, Object>> headersConsumer) {
			headersConsumer.accept(this.headers);
			return this;
		}

		/**
		 * Use this audience in the resulting {@link Jwt}
		 * @param audience The audience(s) to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder audience(Collection<String> audience) {
			return claim(AUD, audience);
		}

		/**
		 * Use this expiration in the resulting {@link Jwt}
		 * @param expiresAt The expiration to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder expiresAt(Instant expiresAt) {
			this.claim(EXP, expiresAt);
			return this;
		}

		/**
		 * Use this identifier in the resulting {@link Jwt}
		 * @param jti The identifier to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder jti(String jti) {
			this.claim(JTI, jti);
			return this;
		}

		/**
		 * Use this issued-at timestamp in the resulting {@link Jwt}
		 * @param issuedAt The issued-at timestamp to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder issuedAt(Instant issuedAt) {
			this.claim(IAT, issuedAt);
			return this;
		}

		/**
		 * Use this issuer in the resulting {@link Jwt}
		 * @param issuer The issuer to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder issuer(String issuer) {
			this.claim(ISS, issuer);
			return this;
		}

		/**
		 * Use this not-before timestamp in the resulting {@link Jwt}
		 * @param notBefore The not-before timestamp to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder notBefore(Instant notBefore) {
			this.claim(NBF, notBefore);
			return this;
		}

		/**
		 * Use this subject in the resulting {@link Jwt}
		 * @param subject The subject to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder subject(String subject) {
			this.claim(SUB, subject);
			return this;
		}

		/**
		 * Build the {@link Jwt}
		 * @return The constructed {@link Jwt}
		 */
		public Jwt build() {
			Instant iat = toInstant(this.claims.get(IAT));
			Instant exp = toInstant(this.claims.get(EXP));
			return new Jwt(this.tokenValue, iat, exp, this.headers, this.claims);
		}

		private Instant toInstant(Object timestamp) {
			if (timestamp != null) {
				Assert.isInstanceOf(Instant.class, timestamp, "timestamps must be of type Instant");
			}
			return (Instant) timestamp;
		}

	}

}
