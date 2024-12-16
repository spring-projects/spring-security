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

package org.springframework.security.web.webauthn.api;

public final class TestPublicKeyCredential {

	public static PublicKeyCredential.PublicKeyCredentialBuilder<AuthenticatorAttestationResponse> createPublicKeyCredential() {
		AuthenticatorAttestationResponse response = TestAuthenticatorAttestationResponse
			.createAuthenticatorAttestationResponse()
			.build();
		return createPublicKeyCredential(response);
	}

	public static <R extends AuthenticatorResponse> PublicKeyCredential.PublicKeyCredentialBuilder<R> createPublicKeyCredential(
			R response) {
		ImmutableAuthenticationExtensionsClientOutputs clientExtensionResults = new ImmutableAuthenticationExtensionsClientOutputs(
				new CredentialPropertiesOutput(false));
		return PublicKeyCredential.builder()
			.id("AX6nVVERrH6opMafUGn3Z9EyNEy6cftfBKV_2YxYl1jdW8CSJxMKGXFV3bnrKTiMSJeInkG7C6B2lPt8E5i3KaM")
			.rawId(Bytes
				.fromBase64("AX6nVVERrH6opMafUGn3Z9EyNEy6cftfBKV_2YxYl1jdW8CSJxMKGXFV3bnrKTiMSJeInkG7C6B2lPt8E5i3KaM"))
			.response(response)
			.type(PublicKeyCredentialType.PUBLIC_KEY)
			.clientExtensionResults(clientExtensionResults);
	}

	private TestPublicKeyCredential() {
	}

}
