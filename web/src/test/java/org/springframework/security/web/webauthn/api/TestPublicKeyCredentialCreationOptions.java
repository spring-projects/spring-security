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

import java.time.Duration;

public final class TestPublicKeyCredentialCreationOptions {

	public static PublicKeyCredentialCreationOptions.PublicKeyCredentialCreationOptionsBuilder createPublicKeyCredentialCreationOptions() {

		AuthenticatorSelectionCriteria authenticatorSelection = AuthenticatorSelectionCriteria.builder()
			.userVerification(UserVerificationRequirement.PREFERRED)
			.residentKey(ResidentKeyRequirement.REQUIRED)
			.build();
		Bytes challenge = Bytes.fromBase64("q7lCdd3SVQxdC-v8pnRAGEn1B2M-t7ZECWPwCAmhWvc");
		PublicKeyCredentialRpEntity rp = PublicKeyCredentialRpEntity.builder()
			.id("example.localhost")
			.name("SimpleWebAuthn Example")
			.build();
		Bytes userId = Bytes.fromBase64("oWJtkJ6vJ_m5b84LB4_K7QKTCTEwLIjCh4tFMCGHO4w");
		PublicKeyCredentialUserEntity userEntity = ImmutablePublicKeyCredentialUserEntity.builder()
			.displayName("user@example.localhost")
			.id(userId)
			.name("user@example.localhost")
			.build();
		ImmutableAuthenticationExtensionsClientInputs clientInputs = new ImmutableAuthenticationExtensionsClientInputs(
				ImmutableAuthenticationExtensionsClientInput.credProps);
		return PublicKeyCredentialCreationOptions.builder()
			.attestation(AttestationConveyancePreference.NONE)
			.user(userEntity)
			.pubKeyCredParams(PublicKeyCredentialParameters.EdDSA, PublicKeyCredentialParameters.ES256,
					PublicKeyCredentialParameters.RS256)
			.authenticatorSelection(authenticatorSelection)
			.challenge(challenge)
			.rp(rp)
			.extensions(clientInputs)
			.timeout(Duration.ofMinutes(5));
	}

	private TestPublicKeyCredentialCreationOptions() {
	}

}
