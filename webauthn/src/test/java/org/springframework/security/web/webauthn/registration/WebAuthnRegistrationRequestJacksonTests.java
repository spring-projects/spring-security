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

package org.springframework.security.web.webauthn.registration;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.web.webauthn.api.AuthenticatorAttachment;
import org.springframework.security.web.webauthn.api.AuthenticatorAttestationResponse;
import org.springframework.security.web.webauthn.api.AuthenticatorTransport;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialPropertiesOutput;
import org.springframework.security.web.webauthn.api.ImmutableAuthenticationExtensionsClientOutputs;
import org.springframework.security.web.webauthn.api.PublicKeyCredential;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;
import org.springframework.security.web.webauthn.jackson.PublicKeyCredentialJson;
import org.springframework.security.web.webauthn.jackson.WebauthnJackson2Module;
import org.springframework.security.web.webauthn.management.RelyingPartyPublicKey;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 * @since 6.4
 */
class WebAuthnRegistrationRequestJacksonTests {

	private ObjectMapper mapper;

	@BeforeEach
	void setup() {
		this.mapper = new ObjectMapper();
		this.mapper.registerModule(new WebauthnJackson2Module());
	}

	@Test
	void readRelyingPartyRequest() throws Exception {
		String json = """
				{
					"publicKey": {
						"label": "Cell Phone",
						"credential": %s
					}
				}
				""".formatted(PublicKeyCredentialJson.PUBLIC_KEY_JSON);
		WebAuthnRegistrationFilter.WebAuthnRegistrationRequest registrationRequest = this.mapper.readValue(json,
				WebAuthnRegistrationFilter.WebAuthnRegistrationRequest.class);

		ImmutableAuthenticationExtensionsClientOutputs clientExtensionResults = new ImmutableAuthenticationExtensionsClientOutputs(
				new CredentialPropertiesOutput(false));

		PublicKeyCredential<AuthenticatorAttestationResponse> credential = PublicKeyCredential.builder()
			.id("AX6nVVERrH6opMafUGn3Z9EyNEy6cftfBKV_2YxYl1jdW8CSJxMKGXFV3bnrKTiMSJeInkG7C6B2lPt8E5i3KaM")
			.rawId(Bytes
				.fromBase64("AX6nVVERrH6opMafUGn3Z9EyNEy6cftfBKV_2YxYl1jdW8CSJxMKGXFV3bnrKTiMSJeInkG7C6B2lPt8E5i3KaM"))
			.response(AuthenticatorAttestationResponse.builder()
				.attestationObject(Bytes.fromBase64(
						"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjFSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQF-p1VREax-qKTGn1Bp92fRMjRMunH7XwSlf9mMWJdY3VvAkicTChlxVd256yk4jEiXiJ5BuwugdpT7fBOYtymjpQECAyYgASFYIJK-2epPEw0ujHN-gvVp2Hp3ef8CzU3zqwO5ylx8L2OsIlggK5x5OlTGEPxLS-85TAABum4aqVK4CSWJ7LYDdkjuBLk"))
				.clientDataJSON(Bytes.fromBase64(
						"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiSUJRbnVZMVowSzFIcUJvRldDcDJ4bEpsOC1vcV9hRklYenlUX0YwLTBHVSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0"))
				.transports(AuthenticatorTransport.HYBRID, AuthenticatorTransport.INTERNAL)
				.build())
			.type(PublicKeyCredentialType.PUBLIC_KEY)
			.clientExtensionResults(clientExtensionResults)
			.authenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM)
			.build();

		WebAuthnRegistrationFilter.WebAuthnRegistrationRequest expected = new WebAuthnRegistrationFilter.WebAuthnRegistrationRequest();
		expected.setPublicKey(new RelyingPartyPublicKey(credential, "Cell Phone"));
		assertThat(registrationRequest).usingRecursiveComparison().isEqualTo(expected);
	}

}
