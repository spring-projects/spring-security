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

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.time.Instant;

/**
 * Base class for <i>Security Token</i> implementations.
 *
 * <p>
 * It is highly recommended that implementations be immutable.
 *
 * @author Joe Grandja
 * @since 5.0
 */
public abstract class AbstractToken implements Serializable {
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	private final String tokenValue;
	private final Instant issuedAt;
	private final Instant expiresAt;

	protected AbstractToken(String tokenValue, Instant issuedAt, Instant expiresAt) {
		Assert.hasLength(tokenValue, "tokenValue cannot be empty");
		Assert.notNull(issuedAt, "issuedAt cannot be null");
		Assert.notNull(expiresAt, "expiresAt cannot be null");
		this.tokenValue = tokenValue;
		this.issuedAt = issuedAt;
		this.expiresAt = expiresAt;
	}

	public String getTokenValue() {
		return this.tokenValue;
	}

	public Instant getIssuedAt() {
		return this.issuedAt;
	}

	public Instant getExpiresAt() {
		return this.expiresAt;
	}
}
