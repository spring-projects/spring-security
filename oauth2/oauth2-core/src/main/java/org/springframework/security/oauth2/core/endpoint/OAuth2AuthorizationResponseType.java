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
package org.springframework.security.oauth2.core.endpoint;

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

import java.io.Serializable;

/**
 * The {@code response_type} parameter is consumed by the authorization endpoint which
 * is used by the authorization code grant type and implicit grant type.
 * The client sets the {@code response_type} parameter with the desired grant type before initiating the authorization request.
 *
 * <p>
 * The {@code response_type} parameter value may be one of &quot;code&quot; for requesting an authorization code or
 * &quot;token&quot; for requesting an access token (implicit grant).

 * @author Joe Grandja
 * @since 5.0
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-3.1.1">Section 3.1.1 Response Type</a>
 */
public final class OAuth2AuthorizationResponseType implements Serializable {
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	public static final OAuth2AuthorizationResponseType CODE = new OAuth2AuthorizationResponseType("code");
	public static final OAuth2AuthorizationResponseType TOKEN = new OAuth2AuthorizationResponseType("token");
	private final String value;

	private OAuth2AuthorizationResponseType(String value) {
		Assert.hasText(value, "value cannot be empty");
		this.value = value;
	}

	/**
	 * Returns the value of the authorization response type.
	 *
	 * @return the value of the authorization response type
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
		OAuth2AuthorizationResponseType that = (OAuth2AuthorizationResponseType) obj;
		return this.getValue().equals(that.getValue());
	}

	@Override
	public int hashCode() {
		return this.getValue().hashCode();
	}
}
