/*
 * Copyright 2002-2022 the original author or authors.
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

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

/**
 * An authorization grant is a credential representing the resource owner's authorization
 * (to access it's protected resources) to the client and used by the client to obtain an
 * access token.
 *
 * <p>
 * The OAuth 2.0 Authorization Framework defines four standard grant types: authorization
 * code, resource owner password credentials, and client credentials. It also provides an
 * extensibility mechanism for defining additional grant types.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-1.3">Section
 * 1.3 Authorization Grant</a>
 */
public final class AuthorizationGrantType implements Serializable {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	public static final AuthorizationGrantType AUTHORIZATION_CODE = new AuthorizationGrantType("authorization_code");

	public static final AuthorizationGrantType REFRESH_TOKEN = new AuthorizationGrantType("refresh_token");

	public static final AuthorizationGrantType CLIENT_CREDENTIALS = new AuthorizationGrantType("client_credentials");

	/**
	 * @deprecated The latest OAuth 2.0 Security Best Current Practice disallows the use
	 * of the Resource Owner Password Credentials grant. See reference
	 * <a target="_blank" href=
	 * "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-19#section-2.4">OAuth
	 * 2.0 Security Best Current Practice.</a>
	 */
	@Deprecated
	public static final AuthorizationGrantType PASSWORD = new AuthorizationGrantType("password");

	/**
	 * @since 5.5
	 */
	public static final AuthorizationGrantType JWT_BEARER = new AuthorizationGrantType(
			"urn:ietf:params:oauth:grant-type:jwt-bearer");

	private final String value;

	/**
	 * Constructs an {@code AuthorizationGrantType} using the provided value.
	 * @param value the value of the authorization grant type
	 */
	public AuthorizationGrantType(String value) {
		Assert.hasText(value, "value cannot be empty");
		this.value = value;
	}

	/**
	 * Returns the value of the authorization grant type.
	 * @return the value of the authorization grant type
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
		AuthorizationGrantType that = (AuthorizationGrantType) obj;
		return this.getValue().equals(that.getValue());
	}

	@Override
	public int hashCode() {
		return this.getValue().hashCode();
	}

}
