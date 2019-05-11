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
package org.springframework.security.oauth2.jwt;

import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.net.URL;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * An implementation of an {@link AbstractOAuth2Token} representing a JSON Web Token (JWT).
 *
 * <p>
 * JWTs represent a set of &quot;claims&quot; as a JSON object that may be encoded in a
 * JSON Web Signature (JWS) and/or JSON Web Encryption (JWE) structure.
 * The JSON object, also known as the JWT Claims Set, consists of one or more claim name/value pairs.
 * The claim name is a {@code String} and the claim value is an arbitrary JSON object.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AbstractOAuth2Token
 * @see JwtClaimAccessor
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JSON Web Token (JWT)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515">JSON Web Signature (JWS)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7516">JSON Web Encryption (JWE)</a>
 */
public class Jwt extends AbstractOAuth2Token implements JwtClaimAccessor {
	private final Map<String, Object> headers;
	private final Map<String, Object> claims;

	/**
	 * Constructs a {@code Jwt} using the provided parameters.
	 *
	 * @param tokenValue the token value
	 * @param issuedAt the time at which the JWT was issued
	 * @param expiresAt the expiration time on or after which the JWT MUST NOT be accepted
	 * @param headers the JOSE header(s)
	 * @param claims the JWT Claims Set
	 */
	public Jwt(String tokenValue, Instant issuedAt, Instant expiresAt,
				Map<String, Object> headers, Map<String, Object> claims) {
		super(tokenValue, issuedAt, expiresAt);
		Assert.notEmpty(headers, "headers cannot be empty");
		Assert.notEmpty(claims, "claims cannot be empty");
		this.headers = Collections.unmodifiableMap(new LinkedHashMap<>(headers));
		this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
	}

	/**
	 * Returns the JOSE header(s).
	 *
	 * @return a {@code Map} of the JOSE header(s)
	 */
	public Map<String, Object> getHeaders() {
		return this.headers;
	}

	/**
	 * Returns the JWT Claims Set.
	 *
	 * @return a {@code Map} of the JWT Claims Set
	 */
	@Override
	public Map<String, Object> getClaims() {
		return this.claims;
	}
	
	/**
	 * Helps configure a {@link Jwt}
	 *
	 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
	 */
	public static class Builder implements JwtClaimAccessor {
		private String tokenValue;
		private final Map<String, Object> claims = new HashMap<>();
		private final Map<String, Object> headers = new HashMap<>();

		public Builder tokenValue(String tokenValue) {
			this.tokenValue = tokenValue;
			return this;
		}

		public Builder claim(String name, Object value) {
			this.claims.put(name, value);
			return this;
		}

		public Builder clearClaims(Map<String, Object> claims) {
			this.claims.clear();
			return this;
		}

		/**
		 * Adds to existing claims (does not replace existing ones)
		 * @param claims claims to add
		 * @return this builder to further configure
		 */
		public Builder claims(Map<String, Object> claims) {
			this.claims.putAll(claims);
			return this;
		}

		public Builder header(String name, Object value) {
			this.headers.put(name, value);
			return this;
		}

		public Builder clearHeaders(Map<String, Object> headers) {
			this.headers.clear();
			return this;
		}

		/**
		 * Adds to existing headers (does not replace existing ones)
		 * @param headers headers to add
		 * @return this builder to further configure
		 */
		public Builder headers(Map<String, Object> headers) {
			headers.entrySet().stream().forEach(e -> this.header(e.getKey(), e.getValue()));
			return this;
		}

		public Jwt build() {
			Assert.isTrue(hasTokenValue(), "token value must be set");
			Assert.isTrue(hasName(), "name must be set");
			Assert.isTrue(hasHeader(), "at least one header must be set");
			return new Jwt(
					this.tokenValue,
					getClaimAsInstant(JwtClaimNames.IAT),
					getClaimAsInstant(JwtClaimNames.EXP),
					new HashMap<>(this.headers),
					new HashMap<>(this.claims));
		}

		@Override
		public Map<String, Object> getClaims() {
			return Collections.unmodifiableMap(this.claims);
		}

		public Builder audience(Stream<String> audience) {
			this.claim(JwtClaimNames.AUD, audience.collect(Collectors.toList()));
			return this;
		}

		public Builder audience(String... audience) {
			return audience(Stream.of(audience));
		}

		public Builder expiresAt(Instant expiresAt) {
			this.claim(JwtClaimNames.EXP, expiresAt.getEpochSecond());
			return this;
		}

		public Builder jti(String jti) {
			this.claim(JwtClaimNames.JTI, jti);
			return this;
		}

		public Builder issuedAt(Instant issuedAt) {
			this.claim(JwtClaimNames.IAT, issuedAt.getEpochSecond());
			return this;
		}

		public Builder issuer(URL issuer) {
			this.claim(JwtClaimNames.ISS, issuer.toString());
			return this;
		}

		public Builder notBefore(Instant notBefore) {
			this.claim(JwtClaimNames.NBF, notBefore.getEpochSecond());
			return this;
		}

		public Builder subject(String subject) {
			this.claim(JwtClaimNames.SUB, subject);
			return this;
		}

		public boolean hasTokenValue() {
			return StringUtils.hasLength(tokenValue);
		}

		public boolean hasName() {
			return StringUtils.hasLength(getClaimAsString(JwtClaimNames.SUB));
		}

		public boolean hasHeader() {
			return this.headers.size() > 0;
		}
	}
}
