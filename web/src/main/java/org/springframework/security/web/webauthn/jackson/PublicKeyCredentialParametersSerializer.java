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

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialParameters;

import java.io.IOException;

/**
 * Jackson serializer for {@link PublicKeyCredentialParameters}
 *
 * @author Justin Cranford
 * @since 6.5
 */
@SuppressWarnings("serial")
public class PublicKeyCredentialParametersSerializer extends StdSerializer<PublicKeyCredentialParameters> {

    public PublicKeyCredentialParametersSerializer() {
        super(PublicKeyCredentialParameters.class);
    }

    @Override
    public void serialize(PublicKeyCredentialParameters value, JsonGenerator gen, SerializerProvider provider) throws IOException {
        gen.writeStartObject();
		if (value.getType() != null) {
			gen.writeFieldName("type");
			gen.writeString(value.getType().getValue());
		}
		if (value.getAlg() != null) {
			gen.writeFieldName("alg");
			gen.writeNumber(value.getAlg().getValue());
		}
        gen.writeEndObject();
    }
}
