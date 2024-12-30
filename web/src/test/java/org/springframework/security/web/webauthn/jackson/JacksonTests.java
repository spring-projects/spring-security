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

import java.time.Duration;
import java.util.Arrays;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientOutputs;
import org.springframework.security.web.webauthn.api.AuthenticatorAssertionResponse;
import org.springframework.security.web.webauthn.api.AuthenticatorAttachment;
import org.springframework.security.web.webauthn.api.AuthenticatorAttestationResponse;
import org.springframework.security.web.webauthn.api.AuthenticatorTransport;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialPropertiesOutput;
import org.springframework.security.web.webauthn.api.ImmutableAuthenticationExtensionsClientInput;
import org.springframework.security.web.webauthn.api.ImmutableAuthenticationExtensionsClientInputs;
import org.springframework.security.web.webauthn.api.ImmutableAuthenticationExtensionsClientOutputs;
import org.springframework.security.web.webauthn.api.PublicKeyCredential;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;
import org.springframework.security.web.webauthn.api.TestPublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.UserVerificationRequirement;

import static org.assertj.core.api.Assertions.assertThat;

class JacksonTests {

	private ObjectMapper mapper;

	@BeforeEach
	void setup() {
		this.mapper = new ObjectMapper();
		this.mapper.registerModule(new WebauthnJackson2Module());
	}

	@Test
	void readAuthenticatorTransport() throws Exception {
		AuthenticatorTransport transport = this.mapper.readValue("\"hybrid\"", AuthenticatorTransport.class);

		assertThat(transport).isEqualTo(AuthenticatorTransport.HYBRID);
	}

	@Test
	void readAuthenticatorAttachment() throws Exception {
		AuthenticatorAttachment value = this.mapper.readValue("\"cross-platform\"", AuthenticatorAttachment.class);
		assertThat(value).isEqualTo(AuthenticatorAttachment.CROSS_PLATFORM);
	}

	@Test
	void writeAuthenticatorAttachment() throws Exception {
		String value = this.mapper.writeValueAsString(AuthenticatorAttachment.CROSS_PLATFORM);
		assertThat(value).isEqualTo("\"cross-platform\"");
	}

	@Test
	void readAuthenticationExtensionsClientOutputs() throws Exception {
		String json = """
				{
					"credProps": {
						"rk": false
					}
				}
				""";
		ImmutableAuthenticationExtensionsClientOutputs clientExtensionResults = new ImmutableAuthenticationExtensionsClientOutputs(
				new CredentialPropertiesOutput(false));

		AuthenticationExtensionsClientOutputs outputs = this.mapper.readValue(json,
				AuthenticationExtensionsClientOutputs.class);
		assertThat(outputs).usingRecursiveComparison().isEqualTo(clientExtensionResults);
	}

	@Test
	void readAuthenticationExtensionsClientOutputsWhenAuthenticatorDisplayName() throws Exception {
		String json = """
				{
					"credProps": {
						"rk": false,
						"authenticatorDisplayName": "1Password"
					}
				}
				""";
		ImmutableAuthenticationExtensionsClientOutputs clientExtensionResults = new ImmutableAuthenticationExtensionsClientOutputs(
				new CredentialPropertiesOutput(false));

		AuthenticationExtensionsClientOutputs outputs = this.mapper.readValue(json,
				AuthenticationExtensionsClientOutputs.class);
		assertThat(outputs).usingRecursiveComparison().isEqualTo(clientExtensionResults);
	}

	@Test
	void readCredPropsWhenAuthenticatorDisplayName() throws Exception {
		String json = """
				{
					"rk": false,
					"authenticatorDisplayName": "1Password"
				}
				""";
		CredentialPropertiesOutput credProps = new CredentialPropertiesOutput(false);

		CredentialPropertiesOutput outputs = this.mapper.readValue(json, CredentialPropertiesOutput.class);
		assertThat(outputs).usingRecursiveComparison().isEqualTo(credProps);
	}

	@Test
	void readAuthenticationExtensionsClientOutputsWhenFieldAfter() throws Exception {
		String json = """
				{
					"clientOutputs": {
						"credProps": {
							"rk": false
						}
					},
					"label": "Cell Phone"
				}
				""";
		ImmutableAuthenticationExtensionsClientOutputs clientExtensionResults = new ImmutableAuthenticationExtensionsClientOutputs(
				new CredentialPropertiesOutput(false));

		ClassWithOutputsAndAnotherField expected = new ClassWithOutputsAndAnotherField();
		expected.setClientOutputs(clientExtensionResults);
		expected.setLabel("Cell Phone");

		ClassWithOutputsAndAnotherField actual = this.mapper.readValue(json, ClassWithOutputsAndAnotherField.class);
		assertThat(actual).usingRecursiveComparison().isEqualTo(expected);
	}

	@Test
	void writePublicKeyCredentialCreationOptions() throws Exception {
		String expected = """
				{
				    "attestation": "none",
				    "authenticatorSelection": {
				        "residentKey": "required"
				    },
				    "challenge": "q7lCdd3SVQxdC-v8pnRAGEn1B2M-t7ZECWPwCAmhWvc",
				    "excludeCredentials": [],
				    "extensions": {
				        "credProps": true
				    },
				    "pubKeyCredParams": [
				        {
				            "alg": -7,
				            "type": "public-key"
				        },{
				            "alg": -8,
				            "type": "public-key"
				        },
				        {
				            "alg": -257,
				            "type": "public-key"
				        }
				    ],
				    "rp": {
				        "id": "example.localhost",
				        "name": "SimpleWebAuthn Example"
				    },
				    "timeout": 300000,
				    "user": {
				        "displayName": "user@example.localhost",
				        "id": "oWJtkJ6vJ_m5b84LB4_K7QKTCTEwLIjCh4tFMCGHO4w",
				        "name": "user@example.localhost"
				    }
				}
				""";

		PublicKeyCredentialCreationOptions options = TestPublicKeyCredentialCreationOptions
			.createPublicKeyCredentialCreationOptions()
			.build();

		String string = this.mapper.writeValueAsString(options);

		JSONAssert.assertEquals(expected, string, false);
	}

	@Test
	void readPublicKeyCredentialAuthenticatorAttestationResponse() throws Exception {

		PublicKeyCredential<AuthenticatorAttestationResponse> publicKeyCredential = this.mapper.readValue(
				PublicKeyCredentialJson.PUBLIC_KEY_JSON,
				new TypeReference<PublicKeyCredential<AuthenticatorAttestationResponse>>() {
				});

		ImmutableAuthenticationExtensionsClientOutputs clientExtensionResults = new ImmutableAuthenticationExtensionsClientOutputs(
				new CredentialPropertiesOutput(false));

		PublicKeyCredential<AuthenticatorAttestationResponse> expected = PublicKeyCredential.builder()
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

		assertThat(publicKeyCredential).usingRecursiveComparison().isEqualTo(expected);
	}

	@Test
	void readPublicKeyCredentialAuthenticatorAttestationResponseWhenExtraFields() throws Exception {
		final String json = """
				{
					 "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjFSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQF-p1VREax-qKTGn1Bp92fRMjRMunH7XwSlf9mMWJdY3VvAkicTChlxVd256yk4jEiXiJ5BuwugdpT7fBOYtymjpQECAyYgASFYIJK-2epPEw0ujHN-gvVp2Hp3ef8CzU3zqwO5ylx8L2OsIlggK5x5OlTGEPxLS-85TAABum4aqVK4CSWJ7LYDdkjuBLk",
					 "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiSUJRbnVZMVowSzFIcUJvRldDcDJ4bEpsOC1vcV9hRklYenlUX0YwLTBHVSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
					 "transports": [
					   "hybrid",
					   "internal"
					 ],
					 "publicKeyAlgorithm": -7,
					 "publicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkr7Z6k8TDS6Mc36C9WnYend5_wLNTfOrA7nKXHwvY6wrnHk6VMYQ_EtL7zlMAAG6bhqpUrgJJYnstgN2SO4EuQ",
					 "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQF-p1VREax-qKTGn1Bp92fRMjRMunH7XwSlf9mMWJdY3VvAkicTChlxVd256yk4jEiXiJ5BuwugdpT7fBOYtymjpQECAyYgASFYIJK-2epPEw0ujHN-gvVp2Hp3ef8CzU3zqwO5ylx8L2OsIlggK5x5OlTGEPxLS-85TAABum4aqVK4CSWJ7LYDdkjuBLk"
				}
				""";
		AuthenticatorAttestationResponse response = this.mapper.readValue(json, AuthenticatorAttestationResponse.class);

		ImmutableAuthenticationExtensionsClientOutputs clientExtensionResults = new ImmutableAuthenticationExtensionsClientOutputs(
				new CredentialPropertiesOutput(false));

		AuthenticatorAttestationResponse expected = AuthenticatorAttestationResponse.builder()
			.attestationObject(Bytes.fromBase64(
					"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjFSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQF-p1VREax-qKTGn1Bp92fRMjRMunH7XwSlf9mMWJdY3VvAkicTChlxVd256yk4jEiXiJ5BuwugdpT7fBOYtymjpQECAyYgASFYIJK-2epPEw0ujHN-gvVp2Hp3ef8CzU3zqwO5ylx8L2OsIlggK5x5OlTGEPxLS-85TAABum4aqVK4CSWJ7LYDdkjuBLk"))
			.clientDataJSON(Bytes.fromBase64(
					"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiSUJRbnVZMVowSzFIcUJvRldDcDJ4bEpsOC1vcV9hRklYenlUX0YwLTBHVSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0"))
			.transports(AuthenticatorTransport.HYBRID, AuthenticatorTransport.INTERNAL)
			.build();

		assertThat(response).usingRecursiveComparison().isEqualTo(expected);
	}

	@Test
	void writeAuthenticationOptions() throws Exception {
		PublicKeyCredentialRequestOptions credentialRequestOptions = PublicKeyCredentialRequestOptions.builder()
			.allowCredentials(Arrays.asList())
			.challenge(Bytes.fromBase64("I69THX904Q8ONhCgUgOu2PCQCcEjTDiNmokdbgsAsYU"))
			.rpId("example.localhost")
			.timeout(Duration.ofMinutes(5))
			.userVerification(UserVerificationRequirement.REQUIRED)
			.build();
		String actual = this.mapper.writeValueAsString(credentialRequestOptions);

		String expected = """
						{
				    "challenge": "I69THX904Q8ONhCgUgOu2PCQCcEjTDiNmokdbgsAsYU",
				    "allowCredentials": [],
				    "timeout": 300000,
				    "userVerification": "required",
				    "rpId": "example.localhost"
				  }

				""";
		JSONAssert.assertEquals(expected, actual, false);
	}

	@Test
	void readPublicKeyCredentialAuthenticatorAssertionResponse() throws Exception {
		String json = """
					{
					   "id": "IquGb208Fffq2cROa1ZxMg",
					   "rawId": "IquGb208Fffq2cROa1ZxMg",
					   "response": {
						 "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA",
						 "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiaDB2Z3dHUWpvQ3pBekRVc216UHBrLUpWSUpSUmduMEw0S1ZTWU5SY0VaYyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
						 "signature": "MEUCIAdfzPAn3voyXynwa0IXk1S0envMY5KP3NEe9aj4B2BuAiEAm_KJhQoWXdvfhbzwACU3NM4ltQe7_Il46qFUwtpuTdg",
						 "userHandle": "oWJtkJ6vJ_m5b84LB4_K7QKTCTEwLIjCh4tFMCGHO4w"
					   },
					   "type": "public-key",
					   "clientExtensionResults": {},
					   "authenticatorAttachment": "cross-platform"
					 }
				""";
		PublicKeyCredential<AuthenticatorAssertionResponse> publicKeyCredential = this.mapper.readValue(json,
				new TypeReference<PublicKeyCredential<AuthenticatorAssertionResponse>>() {
				});

		ImmutableAuthenticationExtensionsClientOutputs clientExtensionResults = new ImmutableAuthenticationExtensionsClientOutputs();

		PublicKeyCredential<AuthenticatorAssertionResponse> expected = PublicKeyCredential.builder()
			.id("IquGb208Fffq2cROa1ZxMg")
			.rawId(Bytes.fromBase64("IquGb208Fffq2cROa1ZxMg"))
			.response(AuthenticatorAssertionResponse.builder()
				.authenticatorData(Bytes.fromBase64("SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA"))
				.clientDataJSON(Bytes.fromBase64(
						"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiaDB2Z3dHUWpvQ3pBekRVc216UHBrLUpWSUpSUmduMEw0S1ZTWU5SY0VaYyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0"))
				.signature(Bytes.fromBase64(
						"MEUCIAdfzPAn3voyXynwa0IXk1S0envMY5KP3NEe9aj4B2BuAiEAm_KJhQoWXdvfhbzwACU3NM4ltQe7_Il46qFUwtpuTdg"))
				.userHandle(Bytes.fromBase64("oWJtkJ6vJ_m5b84LB4_K7QKTCTEwLIjCh4tFMCGHO4w"))
				.build())
			.type(PublicKeyCredentialType.PUBLIC_KEY)
			.clientExtensionResults(clientExtensionResults)
			.authenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM)
			.build();

		assertThat(publicKeyCredential).usingRecursiveComparison().isEqualTo(expected);
	}

	@Test
	void writeAuthenticationExtensionsClientInputsWhenCredPropsTrue() throws Exception {
		String expected = """
					{
						"credProps": true
					}
				""";

		ImmutableAuthenticationExtensionsClientInputs clientInputs = new ImmutableAuthenticationExtensionsClientInputs(
				ImmutableAuthenticationExtensionsClientInput.credProps);

		String actual = this.mapper.writeValueAsString(clientInputs);

		JSONAssert.assertEquals(expected, actual, false);
	}

	public static class ClassWithOutputsAndAnotherField {

		private String label;

		private AuthenticationExtensionsClientOutputs clientOutputs;

		public String getLabel() {
			return this.label;
		}

		public void setLabel(String label) {
			this.label = label;
		}

		public AuthenticationExtensionsClientOutputs getClientOutputs() {
			return this.clientOutputs;
		}

		public void setClientOutputs(AuthenticationExtensionsClientOutputs clientOutputs) {
			this.clientOutputs = clientOutputs;
		}

	}

}
