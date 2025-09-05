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

package org.springframework.security.oauth2.server.authorization.settings;

import java.io.Serial;
import java.io.Serializable;

import org.springframework.util.Assert;

/**
 * Standard data formats for OAuth 2.0 Tokens.
 *
 * @author Joe Grandja
 * @since 0.2.3
 */
public final class OAuth2TokenFormat implements Serializable {

	@Serial
	private static final long serialVersionUID = -3808658977410337294L;

	/**
	 * Self-contained tokens use a protected, time-limited data structure that contains
	 * token metadata and claims of the user and/or client. JSON Web Token (JWT) is a
	 * widely used format.
	 */
	public static final OAuth2TokenFormat SELF_CONTAINED = new OAuth2TokenFormat("self-contained");

	/**
	 * Reference (opaque) tokens are unique identifiers that serve as a reference to the
	 * token metadata and claims of the user and/or client, stored at the provider.
	 */
	public static final OAuth2TokenFormat REFERENCE = new OAuth2TokenFormat("reference");

	private final String value;

	/**
	 * Constructs an {@code OAuth2TokenFormat} using the provided value.
	 * @param value the value of the token format
	 */
	public OAuth2TokenFormat(String value) {
		Assert.hasText(value, "value cannot be empty");
		this.value = value;
	}

	/**
	 * Returns the value of the token format.
	 * @return the value of the token format
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
		OAuth2TokenFormat that = (OAuth2TokenFormat) obj;
		return getValue().equals(that.getValue());
	}

	@Override
	public int hashCode() {
		return getValue().hashCode();
	}

}
