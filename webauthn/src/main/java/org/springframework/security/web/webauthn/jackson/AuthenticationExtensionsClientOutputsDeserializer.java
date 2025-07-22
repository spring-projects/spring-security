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
 */
@SuppressWarnings("serial")
class AuthenticationExtensionsClientOutputsDeserializer extends StdDeserializer<AuthenticationExtensionsClientOutputs> {

	private static final Log logger = LogFactory.getLog(AuthenticationExtensionsClientOutputsDeserializer.class);

	/**
	 * Creates a new instance.
	 */
	AuthenticationExtensionsClientOutputsDeserializer() {
		super(AuthenticationExtensionsClientOutputs.class);
	}

	@Override
	public AuthenticationExtensionsClientOutputs deserialize(JsonParser parser, DeserializationContext ctxt)
			throws IOException, JacksonException {
		List<AuthenticationExtensionsClientOutput<?>> outputs = new ArrayList<>();
		for (String key = parser.nextFieldName(); key != null; key = parser.nextFieldName()) {
			JsonToken startObject = parser.nextValue();
			if (startObject != JsonToken.START_OBJECT) {
				break;
			}
			if (CredentialPropertiesOutput.EXTENSION_ID.equals(key)) {
				CredentialPropertiesOutput output = parser.readValueAs(CredentialPropertiesOutput.class);
				outputs.add(output);
			}
			else {
				if (logger.isDebugEnabled()) {
					logger.debug("Skipping unknown extension with id " + key);
				}
				parser.nextValue();
			}
		}

		return new ImmutableAuthenticationExtensionsClientOutputs(outputs);
	}

}
