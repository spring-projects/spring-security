/*
 * Copyright 2002-2017 the original author or authors.
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
 * Base class for <i>OAuth 2.0 Token</i> implementations.
 *
 * @author Joe Grandja
 * @since 5.0
 */
public abstract class AbstractOAuth2Token implements Serializable {
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	private final String tokenValue;
	private final Instant issuedAt;
	private final Instant expiresAt;

	protected AbstractOAuth2Token(String tokenValue, Instant issuedAt, Instant expiresAt) {
		Assert.hasText(tokenValue, "tokenValue cannot be empty");
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

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || this.getClass() != obj.getClass()) {
			return false;
		}

		AbstractOAuth2Token that = (AbstractOAuth2Token) obj;

		if (!this.getTokenValue().equals(that.getTokenValue())) {
			return false;
		}
		if (!this.getIssuedAt().equals(that.getIssuedAt())) {
			return false;
		}
		return this.getExpiresAt().equals(that.getExpiresAt());
	}

	@Override
	public int hashCode() {
		int result = this.getTokenValue().hashCode();
		result = 31 * result + this.getIssuedAt().hashCode();
		result = 31 * result + this.getExpiresAt().hashCode();
		return result;
	}
}
