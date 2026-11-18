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

package org.springframework.security.web.webauthn.api;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AuthenticatorTransportTests {

	@Test
	void usbWhenDeserializedThenSameAsConstant() {
		assertThat(SerializationTestUtils.serializeAndDeserialize(AuthenticatorTransport.USB))
			.isSameAs(AuthenticatorTransport.USB);
	}

	@Test
	void nfcWhenDeserializedThenSameAsConstant() {
		assertThat(SerializationTestUtils.serializeAndDeserialize(AuthenticatorTransport.NFC))
			.isSameAs(AuthenticatorTransport.NFC);
	}

	@Test
	void bleWhenDeserializedThenSameAsConstant() {
		assertThat(SerializationTestUtils.serializeAndDeserialize(AuthenticatorTransport.BLE))
			.isSameAs(AuthenticatorTransport.BLE);
	}

	@Test
	void smartCardWhenDeserializedThenSameAsConstant() {
		assertThat(SerializationTestUtils.serializeAndDeserialize(AuthenticatorTransport.SMART_CARD))
			.isSameAs(AuthenticatorTransport.SMART_CARD);
	}

	@Test
	void hybridWhenDeserializedThenSameAsConstant() {
		assertThat(SerializationTestUtils.serializeAndDeserialize(AuthenticatorTransport.HYBRID))
			.isSameAs(AuthenticatorTransport.HYBRID);
	}

	@Test
	void internalWhenDeserializedThenSameAsConstant() {
		assertThat(SerializationTestUtils.serializeAndDeserialize(AuthenticatorTransport.INTERNAL))
			.isSameAs(AuthenticatorTransport.INTERNAL);
	}

	@Test
	void usbWhenSameValueThenEquals() {
		assertThat(new AuthenticatorTransport("usb")).isEqualTo(AuthenticatorTransport.USB);
	}

	@Test
	void usbWhenSameValueThenHashCodeMatches() {
		assertThat(new AuthenticatorTransport("usb")).hasSameHashCodeAs(AuthenticatorTransport.USB);
	}

	@Test
	void usbWhenDifferentValueThenNotEquals() {
		assertThat(AuthenticatorTransport.USB).isNotEqualTo(AuthenticatorTransport.NFC);
	}

	@Test
	void valuesThenContainsAllAuthenticatorTransports() {
		assertThat(AuthenticatorTransport.values()).containsExactly(AuthenticatorTransport.USB,
				AuthenticatorTransport.NFC, AuthenticatorTransport.BLE, AuthenticatorTransport.SMART_CARD,
				AuthenticatorTransport.HYBRID, AuthenticatorTransport.INTERNAL);
	}

}
