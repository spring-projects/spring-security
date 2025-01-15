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

import org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput;

/**
 * Serializes <a href=
 * "https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-credProtect-extension">credProtect
 * extension</a>.
 *
 * @author Rob Winch
 */
@SuppressWarnings("serial")
class CredProtectAuthenticationExtensionsClientInputSerializer
		extends StdSerializer<CredProtectAuthenticationExtensionsClientInput> {

	protected CredProtectAuthenticationExtensionsClientInputSerializer() {
		super(CredProtectAuthenticationExtensionsClientInput.class);
	}

	@Override
	public void serialize(CredProtectAuthenticationExtensionsClientInput input, JsonGenerator jgen,
			SerializerProvider provider) throws IOException {
		CredProtectAuthenticationExtensionsClientInput.CredProtect credProtect = input.getInput();
		String policy = toString(credProtect.getCredProtectionPolicy());
		jgen.writeObjectField("credentialProtectionPolicy", policy);
		jgen.writeObjectField("enforceCredentialProtectionPolicy", credProtect.isEnforceCredentialProtectionPolicy());
	}

	private static String toString(CredProtectAuthenticationExtensionsClientInput.CredProtect.ProtectionPolicy policy) {
		switch (policy) {
			case USER_VERIFICATION_OPTIONAL:
				return "userVerificationOptional";
			case USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST:
				return "userVerificationOptionalWithCredentialIdList";
			case USER_VERIFICATION_REQUIRED:
				return "userVerificationRequired";
			default:
				throw new IllegalArgumentException("Unsupported ProtectionPolicy " + policy);
		}
	}

}
