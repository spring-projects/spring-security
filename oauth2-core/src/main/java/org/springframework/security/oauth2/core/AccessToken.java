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

import java.time.Duration;
import java.util.Collections;
import java.util.Set;

/**
 * @author Joe Grandja
 */
public class AccessToken extends AbstractToken {
	private final TokenType tokenType;
	private final Duration expiredAt;
	private final Set<String> scopes;

	public enum TokenType {
		BEARER("Bearer"),
		MAC("mac");

		private final String value;

		TokenType(String value) {
			this.value = value;
		}

		public String value() {
			return this.value;
		}
	}

	public AccessToken(TokenType tokenType, String value) {
		this(tokenType, value, Duration.ofSeconds(0));
	}

	public AccessToken(TokenType tokenType, String value, Duration expiredAt) {
		this(tokenType, value, expiredAt, Collections.emptySet());
	}

	public AccessToken(TokenType tokenType, String value, Duration expiredAt, Set<String> scopes) {
		super(value);

		Assert.notNull(tokenType, "tokenType cannot be null");
		this.tokenType = tokenType;

		Assert.notNull(expiredAt, "expiredAt cannot be null");
		this.expiredAt = expiredAt;

		this.scopes = Collections.unmodifiableSet((scopes != null ? scopes : Collections.emptySet()));
	}

	public final TokenType getTokenType() {
		return this.tokenType;
	}

	public final Duration getExpiredAt() {
		return this.expiredAt;
	}

	public final Set<String> getScopes() {
		return this.scopes;
	}
}