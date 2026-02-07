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

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;

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
			throws JacksonException {
		List<AuthenticationExtensionsClientOutput<?>> outputs = new ArrayList<>();
		for (String key = parser.nextName(); key != null; key = parser.nextName()) {
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
