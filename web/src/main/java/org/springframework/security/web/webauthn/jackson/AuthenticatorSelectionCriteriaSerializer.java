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
import org.springframework.security.web.webauthn.api.AuthenticatorSelectionCriteria;

import java.io.IOException;

/**
 * Jackson serializer for {@link AuthenticatorSelectionCriteria}
 *
 * @author Justin Cranford
 * @since 6.5
 */
@SuppressWarnings("serial")
class AuthenticatorSelectionCriteriaSerializer extends StdSerializer<AuthenticatorSelectionCriteria> {

	AuthenticatorSelectionCriteriaSerializer() {
		super(AuthenticatorSelectionCriteria.class);
	}

	@Override
	public void serialize(AuthenticatorSelectionCriteria value, JsonGenerator gen, SerializerProvider provider)
			throws IOException {
		gen.writeStartObject();
		if (value.getAuthenticatorAttachment() != null) {
			gen.writeFieldName("authenticatorAttachment");
			gen.writeString(value.getAuthenticatorAttachment().getValue());
		}
		if (value.getResidentKey() != null) {
			gen.writeFieldName("residentKey");
			gen.writeString(value.getResidentKey().getValue());
		}
		if (value.getUserVerification() != null) {
			gen.writeFieldName("userVerification");
			gen.writeString(value.getUserVerification().getValue());
		}
		gen.writeEndObject();
	}

}
