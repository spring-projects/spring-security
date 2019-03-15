/*
 * Copyright 2002-2017 the original author or authors.
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

import org.springframework.util.Assert;

/**
 * The authentication method used when authenticating the client with the authorization server.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-2.3">Section 2.3 Client Authentication</a>
 */
public final class ClientAuthenticationMethod {
	public static final ClientAuthenticationMethod BASIC = new ClientAuthenticationMethod("basic");
	public static final ClientAuthenticationMethod POST = new ClientAuthenticationMethod("post");
	private final String value;

	/**
	 * Constructs a {@code ClientAuthenticationMethod} using the provided value.
	 *
	 * @param value the value of the client authentication method
	 */
	public ClientAuthenticationMethod(String value) {
		Assert.hasText(value, "value cannot be empty");
		this.value = value;
	}

	/**
	 * Returns the value of the client authentication method.
	 *
	 * @return the value of the client authentication method
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
		ClientAuthenticationMethod that = (ClientAuthenticationMethod) obj;
		return this.getValue().equalsIgnoreCase(that.getValue());
	}

	@Override
	public int hashCode() {
		return this.getValue().hashCode();
	}
}
