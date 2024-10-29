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
 * "https://www.w3.org/TR/webauthn-3/#enumdef-authenticatorattachment">AuthenticatorAttachment</a>.
 *
 * @author Rob Winch
 * @since 6.4
 */
public final class AuthenticatorAttachment {

	/**
	 * Indicates <a href=
	 * "https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#cross-platform-attachment">cross-platform
	 * attachment</a>.
	 *
	 * <p>
	 * Authenticators of this class are removable from, and can "roam" among, client
	 * platforms.
	 */
	public static final AuthenticatorAttachment CROSS_PLATFORM = new AuthenticatorAttachment("cross-platform");

	/**
	 * Indicates <a href=
	 * "https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#platform-attachment">platform
	 * attachment</a>.
	 *
	 * <p>
	 * Usually, authenticators of this class are not removable from the platform.
	 */
	public static final AuthenticatorAttachment PLATFORM = new AuthenticatorAttachment("platform");

	private final String value;

	AuthenticatorAttachment(String value) {
		this.value = value;
	}

	/**
	 * Gets the value.
	 * @return the value.
	 */
	public String getValue() {
		return this.value;
	}

	@Override
	public String toString() {
		return "AuthenticatorAttachment [" + this.value + "]";
	}

	/**
	 * Gets an instance of {@link AuthenticatorAttachment} based upon the value passed in.
	 * @param value the value to obtain the {@link AuthenticatorAttachment}
	 * @return the {@link AuthenticatorAttachment}
	 */
	public static AuthenticatorAttachment valueOf(String value) {
		switch (value) {
			case "cross-platform":
				return CROSS_PLATFORM;
			case "platform":
				return PLATFORM;
			default:
				return new AuthenticatorAttachment(value);
		}
	}

	public static AuthenticatorAttachment[] values() {
		return new AuthenticatorAttachment[] { CROSS_PLATFORM, PLATFORM };
	}

}
