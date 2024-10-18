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

package org.springframework.security.web.webauthn.api;

/**
 * The <a href=
 * "https://www.w3.org/TR/webauthn-3/#enum-credentialType">PublicKeyCredentialType</a>
 * defines the credential types.
 *
 * @author Rob Winch
 * @since 6.4
 */
public final class PublicKeyCredentialType {

	/**
	 * The only credential type that currently exists.
	 */
	public static final PublicKeyCredentialType PUBLIC_KEY = new PublicKeyCredentialType("public-key");

	private final String value;

	private PublicKeyCredentialType(String value) {
		this.value = value;
	}

	/**
	 * Gets the value.
	 * @return the value
	 */
	public String getValue() {
		return this.value;
	}

	public static PublicKeyCredentialType valueOf(String value) {
		if (PUBLIC_KEY.getValue().equals(value)) {
			return PUBLIC_KEY;
		}
		return new PublicKeyCredentialType(value);
	}

}
