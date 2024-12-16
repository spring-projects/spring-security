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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput;
import org.springframework.security.web.webauthn.api.ImmutableAuthenticationExtensionsClientInputs;

/**
 * Test Jackson serialization of CredProtectAuthenticationExtensionsClientInput
 *
 * @author Rob Winch
 */
class CredProtectAuthenticationExtensionsClientInputJacksonTests {

	private ObjectMapper mapper;

	@BeforeEach
	void setup() {
		this.mapper = new ObjectMapper();
		this.mapper.registerModule(new WebauthnJackson2Module());
	}

	@Test
	void writeAuthenticationExtensionsClientInputsWhenCredProtectUserVerificationOptional() throws Exception {
		String expected = """
					{
						"credentialProtectionPolicy": "userVerificationOptional",
						"enforceCredentialProtectionPolicy": true
					}
				""";

		CredProtectAuthenticationExtensionsClientInput.CredProtect credProtect = new CredProtectAuthenticationExtensionsClientInput.CredProtect(
				CredProtectAuthenticationExtensionsClientInput.CredProtect.ProtectionPolicy.USER_VERIFICATION_OPTIONAL,
				true);
		CredProtectAuthenticationExtensionsClientInput credProtectInput = new CredProtectAuthenticationExtensionsClientInput(
				credProtect);
		ImmutableAuthenticationExtensionsClientInputs clientInputs = new ImmutableAuthenticationExtensionsClientInputs(
				credProtectInput);

		String actual = this.mapper.writeValueAsString(clientInputs);

		JSONAssert.assertEquals(expected, actual, false);
	}

	@Test
	void writeAuthenticationExtensionsClientInputsWhenCredProtectUserVerificationOptionalWithCredentialIdList()
			throws Exception {
		String expected = """
					{
						"credentialProtectionPolicy": "userVerificationOptionalWithCredentialIdList",
						"enforceCredentialProtectionPolicy": true
					}
				""";

		CredProtectAuthenticationExtensionsClientInput.CredProtect credProtect = new CredProtectAuthenticationExtensionsClientInput.CredProtect(
				CredProtectAuthenticationExtensionsClientInput.CredProtect.ProtectionPolicy.USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST,
				true);
		CredProtectAuthenticationExtensionsClientInput credProtectInput = new CredProtectAuthenticationExtensionsClientInput(
				credProtect);
		ImmutableAuthenticationExtensionsClientInputs clientInputs = new ImmutableAuthenticationExtensionsClientInputs(
				credProtectInput);

		String actual = this.mapper.writeValueAsString(clientInputs);

		JSONAssert.assertEquals(expected, actual, false);
	}

	@Test
	void writeAuthenticationExtensionsClientInputsWhenCredProtectUserVerificationRequired() throws Exception {
		String expected = """
					{
						"credentialProtectionPolicy": "userVerificationRequired",
						"enforceCredentialProtectionPolicy": true
					}
				""";

		CredProtectAuthenticationExtensionsClientInput.CredProtect credProtect = new CredProtectAuthenticationExtensionsClientInput.CredProtect(
				CredProtectAuthenticationExtensionsClientInput.CredProtect.ProtectionPolicy.USER_VERIFICATION_REQUIRED,
				true);
		CredProtectAuthenticationExtensionsClientInput credProtectInput = new CredProtectAuthenticationExtensionsClientInput(
				credProtect);
		ImmutableAuthenticationExtensionsClientInputs clientInputs = new ImmutableAuthenticationExtensionsClientInputs(
				credProtectInput);

		String actual = this.mapper.writeValueAsString(clientInputs);

		JSONAssert.assertEquals(expected, actual, false);
	}

	@Test
	void writeAuthenticationExtensionsClientInputsWhenEnforceCredentialProtectionPolicyTrue() throws Exception {
		String expected = """
					{
						"credentialProtectionPolicy": "userVerificationOptional",
						"enforceCredentialProtectionPolicy": true
					}
				""";

		CredProtectAuthenticationExtensionsClientInput.CredProtect credProtect = new CredProtectAuthenticationExtensionsClientInput.CredProtect(
				CredProtectAuthenticationExtensionsClientInput.CredProtect.ProtectionPolicy.USER_VERIFICATION_OPTIONAL,
				true);
		CredProtectAuthenticationExtensionsClientInput credProtectInput = new CredProtectAuthenticationExtensionsClientInput(
				credProtect);
		ImmutableAuthenticationExtensionsClientInputs clientInputs = new ImmutableAuthenticationExtensionsClientInputs(
				credProtectInput);

		String actual = this.mapper.writeValueAsString(clientInputs);

		JSONAssert.assertEquals(expected, actual, false);
	}

	@Test
	void writeAuthenticationExtensionsClientInputsWhenEnforceCredentialProtectionPolicyFalse() throws Exception {
		String expected = """
					{
						"credentialProtectionPolicy": "userVerificationOptional",
						"enforceCredentialProtectionPolicy": false
					}
				""";

		CredProtectAuthenticationExtensionsClientInput.CredProtect credProtect = new CredProtectAuthenticationExtensionsClientInput.CredProtect(
				CredProtectAuthenticationExtensionsClientInput.CredProtect.ProtectionPolicy.USER_VERIFICATION_OPTIONAL,
				false);
		CredProtectAuthenticationExtensionsClientInput credProtectInput = new CredProtectAuthenticationExtensionsClientInput(
				credProtect);
		ImmutableAuthenticationExtensionsClientInputs clientInputs = new ImmutableAuthenticationExtensionsClientInputs(
				credProtectInput);

		String actual = this.mapper.writeValueAsString(clientInputs);

		JSONAssert.assertEquals(expected, actual, false);
	}

}
