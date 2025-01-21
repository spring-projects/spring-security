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

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInput;
import org.springframework.security.web.webauthn.api.ImmutableAuthenticationExtensionsClientInput;

import java.io.IOException;

/**
 * Jackson deserializer for {@link AuthenticationExtensionsClientInput}
 *
 * @author Justin Cranford
 * @since 6.5
 */
@SuppressWarnings("serial")
class AuthenticationExtensionsClientInputDeserializer extends StdDeserializer<AuthenticationExtensionsClientInput> {

	AuthenticationExtensionsClientInputDeserializer() {
		super(AuthenticationExtensionsClientInput.class);
	}

	@Override
	public AuthenticationExtensionsClientInput deserialize(JsonParser parser, DeserializationContext ctxt)
			throws IOException {
		if (parser.nextToken() != JsonToken.END_OBJECT) {
			String extensionId = parser.currentName();
			Object value = parser.readValueAs(Object.class);
			return new ImmutableAuthenticationExtensionsClientInput(extensionId, value);
		}
		return null;
	}
}
