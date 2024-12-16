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
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

import org.springframework.security.web.webauthn.api.AuthenticatorTransport;

/**
 * Jackson serializer for {@link AuthenticatorTransport}
 *
 * @author Rob Winch
 * @since 6.4
 */
class AuthenticatorTransportSerializer extends JsonSerializer<AuthenticatorTransport> {

	@Override
	public void serialize(AuthenticatorTransport transport, JsonGenerator jgen, SerializerProvider provider)
			throws IOException {
		jgen.writeString(transport.getValue());
	}

}
