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

package org.springframework.security.authentication.apikey;

import java.time.Instant;
import java.util.Set;

import org.jspecify.annotations.Nullable;

import org.springframework.util.Assert;

/**
 * API key data stored somewhere (e.g., relational database).
 *
 * @author Alexey Razinkov
 * @param id API key ID
 * @param secretHash API key secret hash
 * @param claims API key claim set, can be empty but never {@code null}
 * @param expiresAt Optional expiration moment
 */
public record StoredApiKey(String id, String secretHash, Set<String> claims, @Nullable Instant expiresAt) {

	public StoredApiKey {
		Assert.hasText(secretHash, "API key secret hash must be provided");
		Assert.notNull(claims, "Claim set cannot be null");
	}
}
