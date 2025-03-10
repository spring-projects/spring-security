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
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity.PublicKeyCredentialUserEntityBuilder;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;

import java.io.IOException;

/**
 * Jackson deserializer for {@link PublicKeyCredentialUserEntity}
 *
 * @author Justin Cranford
 * @since 6.5
 */
@SuppressWarnings("serial")
public class PublicKeyCredentialUserEntityDeserializer extends StdDeserializer<PublicKeyCredentialUserEntity> {

    public PublicKeyCredentialUserEntityDeserializer() {
        super(PublicKeyCredentialUserEntity.class);
    }

    @Override
    public PublicKeyCredentialUserEntity deserialize(JsonParser parser, DeserializationContext ctxt)
			throws IOException {
		final PublicKeyCredentialUserEntityBuilder builder = ImmutablePublicKeyCredentialUserEntity.builder();

        while (parser.nextToken() != JsonToken.END_OBJECT) {
            final String fieldName = parser.currentName();
			parser.nextToken();
            if ("id".equals(fieldName)) {
				builder.id(Bytes.fromBase64(parser.getText()));
            } else if ("name".equals(fieldName)) {
				builder.name(parser.getText());
            } else if ("displayName".equals(fieldName)) {
				builder.displayName(parser.getText());
            } else {
				throw new IOException("Unsupported field name: " + fieldName);
            }
        }

        return builder.build();
    }
}
