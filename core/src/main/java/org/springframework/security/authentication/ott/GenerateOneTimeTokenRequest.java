/*
 * Copyright 2002-2025 the original author or authors.
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

import java.time.Duration;

import org.springframework.util.Assert;

/**
 * Class to store information related to an One-Time Token authentication request
 *
 * @author Marcus da Coregio
 * @since 6.4
 */
public class GenerateOneTimeTokenRequest {

	private static final Duration DEFAULT_EXPIRES_IN = Duration.ofMinutes(5);

	private final String username;

	private final Duration expiresIn;

	public GenerateOneTimeTokenRequest(String username) {
		this(username, DEFAULT_EXPIRES_IN);
	}

	public GenerateOneTimeTokenRequest(String username, Duration expiresIn) {
		Assert.hasText(username, "username cannot be empty");
		Assert.notNull(expiresIn, "expiresIn cannot be null");
		this.username = username;
		this.expiresIn = expiresIn;
	}

	public String getUsername() {
		return this.username;
	}

	public Duration getExpiresIn() {
		return this.expiresIn;
	}

}
