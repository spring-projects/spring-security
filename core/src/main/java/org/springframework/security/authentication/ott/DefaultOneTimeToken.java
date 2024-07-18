/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.authentication.ott;

import java.time.Instant;

import org.springframework.util.Assert;

/**
 * A default implementation of {@link OneTimeToken}
 *
 * @author Marcus da Coregio
 * @since 6.4
 */
public class DefaultOneTimeToken implements OneTimeToken {

	private final String token;

	private final String username;

	private final Instant expireAt;

	public DefaultOneTimeToken(String token, String username, Instant expireAt) {
		Assert.hasText(token, "token cannot be empty");
		Assert.hasText(username, "username cannot be empty");
		Assert.notNull(expireAt, "expireAt cannot be null");
		this.token = token;
		this.username = username;
		this.expireAt = expireAt;
	}

	@Override
	public String getTokenValue() {
		return this.token;
	}

	@Override
	public String getUsername() {
		return this.username;
	}

	public Instant getExpiresAt() {
		return this.expireAt;
	}

}
