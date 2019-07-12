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

package org.springframework.security.webauthn.authenticator;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;

/**
 * Authenticators may implement various transports for communicating with clients.
 * This enumeration defines hints as to how clients might communicate with a particular authenticator in order to
 * obtain an assertion for a specific credential. Note that these hints represent the WebAuthn Relying Party's
 * best belief as to how an authenticator may be reached.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#enumdef-authenticatortransport">
 * 5.10.4. Authenticator Transport Enumeration (enum WebAuthnAuthenticatorTransport)</a>
 */
public enum WebAuthnAuthenticatorTransport {

	/**
	 * Indicates the respective authenticator can be contacted over removable USB.
	 */
	USB("usb"),

	/**
	 * Indicates the respective authenticator can be contacted over Near Field Communication (NFC).
	 */
	NFC("nfc"),

	/**
	 * Indicates the respective authenticator can be contacted over Bluetooth Smart
	 * (Bluetooth Low Energy / BLE).
	 */
	BLE("ble");

	private String value;

	WebAuthnAuthenticatorTransport(String value) {
		this.value = value;
	}

	public static WebAuthnAuthenticatorTransport create(String value) {
		if (value == null) {
			return null;
		}
		switch (value) {
			case "usb":
				return USB;
			case "nfc":
				return NFC;
			case "ble":
				return BLE;
			default:
				throw new IllegalArgumentException("value '" + value + "' is out of range");
		}
	}

	@JsonCreator
	private static WebAuthnAuthenticatorTransport deserialize(String value) throws InvalidFormatException {
		try {
			return create(value);
		} catch (IllegalArgumentException e) {
			throw new InvalidFormatException(null, "value is out of range", value, WebAuthnAuthenticatorTransport.class);
		}
	}

	@JsonValue
	public String getValue() {
		return value;
	}

}
