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

package org.springframework.security.web.webauthn.jackson;

import java.io.IOException;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.jspecify.annotations.Nullable;

import org.springframework.security.web.webauthn.api.AuthenticatorTransport;

/**
 * Jackson deserializer for {@link AuthenticatorTransport}
 *
 * @author Rob Winch
 * @since 6.4
 * @deprecated as of 7.0 in favor of
 * {@link org.springframework.security.web.webauthn.jackson.AuthenticatorTransportDeserializer}
 * based on Jackson 3
 */
@Deprecated(forRemoval = true)
@SuppressWarnings("serial")
class AuthenticatorTransportJackson2Deserializer extends StdDeserializer<AuthenticatorTransport> {

	AuthenticatorTransportJackson2Deserializer() {
		super(AuthenticatorTransport.class);
	}

	@Override
	public @Nullable AuthenticatorTransport deserialize(JsonParser parser, DeserializationContext ctxt)
			throws IOException, JacksonException {
		String transportValue = parser.readValueAs(String.class);
		for (AuthenticatorTransport transport : AuthenticatorTransport.values()) {
			if (transport.getValue().equals(transportValue)) {
				return transport;
			}
		}
		return null;
	}

}
