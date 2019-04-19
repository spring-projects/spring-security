/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.oauth2.core;

import java.io.Serializable;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

/**
 * An implementation of an {@link AbstractOAuth2Token} representing an OAuth 2.0 Access Token.
 *
 * <p>
 * An access token is a credential that represents an authorization
 * granted by the resource owner to the client.
 * It is primarily used by the client to access protected resources on either a
 * resource server or the authorization server that originally issued the access token.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-1.4">Section 1.4 Access Token</a>
 */
public class OAuth2AccessToken extends AbstractOAuth2Token implements ClaimAccessor {
	private final TokenType tokenType;
	private final Set<String> scopes;

	/**
	 * Constructs an {@code OAuth2AccessToken} using the provided parameters.
	 *
	 * @param tokenType the token type
	 * @param tokenValue the token value
	 * @param attributes the token attributes
	 */
	public OAuth2AccessToken(final TokenType tokenType, final String tokenValue, final Map<String, Object> attributes) {
		this(tokenType, tokenValue, attributes, Collections.emptySet());
	}
	
	/**
	 * Constructs an {@code OAuth2AccessToken} using the provided parameters.
	 *
	 * @param tokenType the token type
	 * @param tokenValue the token value
	 * @param issuedAt the time at which the token was issued
	 * @param expiresAt the expiration time on or after which the token MUST NOT be accepted
	 * @deprecated since 5.2 provide issue and expiration instants as claims. If non null "issuedAt" is provided and "iat" claim is there too, then first wins (claim is overridden). Same for expiration.
	 */
	@Deprecated
	public OAuth2AccessToken(TokenType tokenType, String tokenValue, Instant issuedAt, Instant expiresAt) {
		this(tokenType, tokenValue, attributes(issuedAt, expiresAt), Collections.emptySet());
	}

	private static Map<String, Object> attributes(final Instant issuedAt, final Instant expiresAt) {
		final Map<String, Object> attributes = new HashMap<>();
		if(issuedAt != null) attributes.put("iat", issuedAt);
		if(expiresAt != null) attributes.put("exp", expiresAt);
		return attributes;
	}

	/**
	 * Constructs an {@code OAuth2AccessToken} using the provided parameters.
	 *
	 * @param tokenType the token type
	 * @param tokenValue the token value
	 * @param issuedAt the time at which the token was issued
	 * @param expiresAt the expiration time on or after which the token MUST NOT be accepted
	 * @param scopes the scope(s) associated to the token
	 */
	public OAuth2AccessToken(TokenType tokenType, String tokenValue, final Map<String, Object> attributes, Set<String> scopes) {
		super(tokenValue, attributes);
		Assert.notNull(tokenType, "tokenType cannot be null");
		this.tokenType = tokenType;
		this.scopes = Collections.unmodifiableSet(
			scopes != null ? scopes : Collections.emptySet());
	}

	/**
	 * Returns the {@link TokenType token type}.
	 *
	 * @return the {@link TokenType}
	 */
	public TokenType getTokenType() {
		return this.tokenType;
	}

	/**
	 * Returns the scope(s) associated to the token.
	 *
	 * @return the scope(s) associated to the token
	 */
	public Set<String> getScopes() {
		return this.scopes;
	}

	/**
	 * Access Token Types.
	 *
	 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-7.1">Section 7.1 Access Token Types</a>
	 */
	public static final class TokenType implements Serializable {
		private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
		public static final TokenType BEARER = new TokenType("Bearer");
		private final String value;

		private TokenType(String value) {
			Assert.hasText(value, "value cannot be empty");
			this.value = value;
		}

		/**
		 * Returns the value of the token type.
		 *
		 * @return the value of the token type
		 */
		public String getValue() {
			return this.value;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null || this.getClass() != obj.getClass()) {
				return false;
			}
			TokenType that = (TokenType) obj;
			return this.getValue().equalsIgnoreCase(that.getValue());
		}

		@Override
		public int hashCode() {
			return this.getValue().hashCode();
		}
	}

	@Override
	public Instant getIssuedAt() {
		return getClaimAsInstant("iat");
	}

	@Override
	public Instant getExpiresAt() {
		return getClaimAsInstant("exp");
	}

	@Override
	public Map<String, Object> getClaims() {
		return getAttributes();
	}
}
