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

import java.util.Set;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PublicKeyCredentialDescriptorTests {

	@Test
	void typeWhenDeserializedThenSameAsConstant() {
		PublicKeyCredentialDescriptor descriptor = PublicKeyCredentialDescriptor.builder()
			.id(TestBytes.get())
			.type(PublicKeyCredentialType.PUBLIC_KEY)
			.build();
		PublicKeyCredentialDescriptor deserialized = SerializationTestUtils.serializeAndDeserialize(descriptor);
		assertThat(deserialized.getType()).isSameAs(PublicKeyCredentialType.PUBLIC_KEY);
	}

	@Test
	void transportsWhenDeserializedThenSameAsConstants() {
		PublicKeyCredentialDescriptor descriptor = PublicKeyCredentialDescriptor.builder()
			.id(TestBytes.get())
			.type(PublicKeyCredentialType.PUBLIC_KEY)
			.transports(Set.of(AuthenticatorTransport.USB, AuthenticatorTransport.HYBRID))
			.build();
		PublicKeyCredentialDescriptor deserialized = SerializationTestUtils.serializeAndDeserialize(descriptor);
		assertThat(deserialized.getTransports()).containsExactlyInAnyOrder(AuthenticatorTransport.USB,
				AuthenticatorTransport.HYBRID);
	}

}
