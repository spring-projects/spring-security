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

package org.springframework.security.web.webauthn.jackson;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test Jackson serialization and deserialization of PublicKeyCredentialRequestOptions
 *
 * @author Justin Cranford
 * @since 6.5
 */
class PublicKeyCredentialRequestOptionsTests {

	private ObjectMapper mapper;

	@BeforeEach
	void setup() {
		this.mapper = new ObjectMapper();
		this.mapper.enable(SerializationFeature.INDENT_OUTPUT);
		this.mapper.registerModule(new WebauthnJackson2Module());
		this.mapper.registerModule(new JavaTimeModule());
	}

	@Test
	public void testSerializeDeserialize() {
		final PublicKeyCredentialRequestOptions given = PublicKeyCredentialRequestOptionsGivens.create();

		final String serialized = assertDoesNotThrow(() -> this.mapper.writeValueAsString(given));
		//System.out.println("serialized:\n" + serialized + "\n\n");

		final PublicKeyCredentialRequestOptions deserialized = assertDoesNotThrow(() -> this.mapper.readValue(serialized, PublicKeyCredentialRequestOptions.class));
		//System.out.println("deserialized:\n" + deserialized + "\n\n");

		final String serializedAgain = assertDoesNotThrow(() -> this.mapper.writeValueAsString(deserialized));
		//System.out.println("serializedAgain:\n" + serializedAgain + "\n\n");

		assertEquals(serialized, serializedAgain);
	}
}
