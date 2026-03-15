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
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientOutput;
import org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientOutputs;
import org.springframework.security.web.webauthn.api.CredentialPropertiesOutput;
import org.springframework.security.web.webauthn.api.ImmutableAuthenticationExtensionsClientOutputs;

/**
 * Provides Jackson deserialization of {@link AuthenticationExtensionsClientOutputs}.
 *
 * @author Rob Winch
 * @since 6.4
 * @deprecated as of 7.0 in favor of
 * {@link org.springframework.security.web.webauthn.jackson.AuthenticationExtensionsClientOutputsDeserializer}
 * based on Jackson 3
 */
@Deprecated(forRemoval = true)
@SuppressWarnings("serial")
class AuthenticationExtensionsClientOutputsJackson2Deserializer
		extends StdDeserializer<AuthenticationExtensionsClientOutputs> {

	private static final Log logger = LogFactory
		.getLog(AuthenticationExtensionsClientOutputsJackson2Deserializer.class);

	/**
	 * Creates a new instance.
	 */
	AuthenticationExtensionsClientOutputsJackson2Deserializer() {
		super(AuthenticationExtensionsClientOutputs.class);
	}

	@Override
	public AuthenticationExtensionsClientOutputs deserialize(JsonParser parser, DeserializationContext ctxt)
			throws IOException, JacksonException {
		List<AuthenticationExtensionsClientOutput<?>> outputs = new ArrayList<>();
		for (String key = parser.nextFieldName(); key != null; key = parser.nextFieldName()) {
			JsonToken next = parser.nextToken();
			if (next == JsonToken.START_OBJECT && CredentialPropertiesOutput.EXTENSION_ID.equals(key)) {
				CredentialPropertiesOutput output = parser.readValueAs(CredentialPropertiesOutput.class);
				outputs.add(output);
			}
			else {
				if (logger.isDebugEnabled()) {
					logger.debug("Skipping unknown extension with id " + key);
				}
				if (next.isStructStart()) {
					parser.skipChildren();
				}
			}
		}

		return new ImmutableAuthenticationExtensionsClientOutputs(outputs);
	}

}
