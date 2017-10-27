/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.core;

import org.springframework.util.Assert;

import java.time.Instant;
import java.util.Collections;
import java.util.Set;

/**
 * An implementation of an {@link AbstractOAuth2Token} representing an <i>OAuth 2.0 Access Token</i>.
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
public class OAuth2AccessToken extends AbstractOAuth2Token {
	private final TokenType tokenType;
	private final Set<String> scopes;

	public OAuth2AccessToken(TokenType tokenType, String tokenValue, Instant issuedAt, Instant expiresAt) {
		this(tokenType, tokenValue, issuedAt, expiresAt, Collections.emptySet());
	}

	public OAuth2AccessToken(TokenType tokenType, String tokenValue, Instant issuedAt, Instant expiresAt, Set<String> scopes) {
		super(tokenValue, issuedAt, expiresAt);
		Assert.notNull(tokenType, "tokenType cannot be null");
		this.tokenType = tokenType;
		this.scopes = Collections.unmodifiableSet(
			scopes != null ? scopes : Collections.emptySet());
	}

	public TokenType getTokenType() {
		return this.tokenType;
	}

	public Set<String> getScopes() {
		return this.scopes;
	}

	public static final class TokenType {
		public static final TokenType BEARER = new TokenType("Bearer");
		private final String value;

		private TokenType(String value) {
			Assert.hasText(value, "value cannot be empty");
			this.value = value;
		}

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
}
