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

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import org.springframework.security.web.webauthn.api.COSEAlgorithmIdentifier;

/**
 * Jackson serializer for {@link COSEAlgorithmIdentifier}
 *
 * @author Rob Winch
 * @since 6.4
 */
class COSEAlgorithmIdentifierDeserializer extends StdDeserializer<COSEAlgorithmIdentifier> {

	COSEAlgorithmIdentifierDeserializer() {
		super(COSEAlgorithmIdentifier.class);
	}

	@Override
	public COSEAlgorithmIdentifier deserialize(JsonParser parser, DeserializationContext ctxt)
			throws IOException, JacksonException {
		Long transportValue = parser.readValueAs(Long.class);
		for (COSEAlgorithmIdentifier identifier : COSEAlgorithmIdentifier.values()) {
			if (identifier.getValue() == transportValue.longValue()) {
				return identifier;
			}
		}
		return null;
	}

}
