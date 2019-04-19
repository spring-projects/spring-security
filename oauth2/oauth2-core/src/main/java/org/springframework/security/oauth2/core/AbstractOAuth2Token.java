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
import java.util.Map;

import org.springframework.lang.Nullable;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

/**
 * Base class for OAuth 2.0 Token implementations.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2AccessToken
 */
public abstract class AbstractOAuth2Token implements Serializable {
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	private final String tokenValue;
	private final Map<String, Object> attributes;

	/**
	 * Sub-class constructor.
	 *
	 * @param tokenValue the token value
	 * @param attributes the token attributes (AKA claims)
	 */
	protected AbstractOAuth2Token(final String tokenValue, final Map<String, Object> attributes) {
		Assert.hasText(tokenValue, "tokenValue cannot be empty");
		this.tokenValue = tokenValue;
		Assert.notEmpty(attributes, "claims cannot be empty");
		this.attributes = Collections.unmodifiableMap(attributes);
		if (getIssuedAt() != null && getExpiresAt() != null) {
			Assert.isTrue(getExpiresAt().isAfter(getIssuedAt()), "expiresAt must be after issuedAt");
		}
	}

	/**
	 * Returns the token value.
	 *
	 * @return the token value
	 */
	public String getTokenValue() {
		return this.tokenValue;
	}

	public Map<String, Object> getAttributes() {
		return attributes;
	}

	/**
	 * Returns the time at which the token was issued.
	 *
	 * @return the time the token was issued or null
	 */
	public abstract @Nullable Instant getIssuedAt();

	/**
	 * Returns the expiration time on or after which the token MUST NOT be accepted.
	 *
	 * @return the expiration time of the token or null
	 */
	public abstract @Nullable Instant getExpiresAt();

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((attributes == null) ? 0 : attributes.hashCode());
		result = prime * result + ((tokenValue == null) ? 0 : tokenValue.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) return true;
		if (obj == null) return false;
		if (getClass() != obj.getClass()) return false;
		AbstractOAuth2Token other = (AbstractOAuth2Token) obj;
		if (attributes == null) {
			if (other.attributes != null) return false;
		} else if (!attributes.equals(other.attributes)) return false;
		if (tokenValue == null) {
			if (other.tokenValue != null) return false;
		} else if (!tokenValue.equals(other.tokenValue)) return false;
		return true;
	}
}
