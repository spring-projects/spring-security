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

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import org.springframework.security.web.webauthn.api.AuthenticatorAttachment;

/**
 * Jackson serializer for {@link AuthenticatorAttachment}
 *
 * @author Rob Winch
 * @since 6.4
 */
@SuppressWarnings("serial")
class AuthenticatorAttachmentSerializer extends StdSerializer<AuthenticatorAttachment> {

	AuthenticatorAttachmentSerializer() {
		super(AuthenticatorAttachment.class);
	}

	@Override
	public void serialize(AuthenticatorAttachment attachment, JsonGenerator jgen, SerializerProvider provider)
			throws IOException {
		jgen.writeString(attachment.getValue());
	}

}
