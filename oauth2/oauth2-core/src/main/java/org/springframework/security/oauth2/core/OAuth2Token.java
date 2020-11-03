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

package org.springframework.security.oauth2.core;

import java.time.Instant;

import org.springframework.lang.Nullable;

/**
 * Core interface representing an OAuth 2.0 Token.
 *
 * @author Joe Grandja
 * @since 5.5
 * @see AbstractOAuth2Token
 */
public interface OAuth2Token {

	/**
	 * Returns the token value.
	 * @return the token value
	 */
	String getTokenValue();

	/**
	 * Returns the time at which the token was issued.
	 * @return the time the token was issued or {@code null}
	 */
	@Nullable
	default Instant getIssuedAt() {
		return null;
	}

	/**
	 * Returns the expiration time on or after which the token MUST NOT be accepted.
	 * @return the token expiration time or {@code null}
	 */
	@Nullable
	default Instant getExpiresAt() {
		return null;
	}

}
