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

import java.time.Instant;
import java.util.Set;

public final class TestCredentialRecord {

	public static ImmutableCredentialRecord.ImmutableCredentialRecordBuilder userCredential() {
		return ImmutableCredentialRecord.builder()
			.label("label")
			.credentialId(Bytes.fromBase64("NauGCN7bZ5jEBwThcde51g"))
			.userEntityUserId(Bytes.fromBase64("vKBFhsWT3gQnn-gHdT4VXIvjDkVXVYg5w8CLGHPunMM"))
			.publicKey(ImmutablePublicKeyCose.fromBase64(
					"pQECAyYgASFYIC7DAiV_trHFPjieOxXbec7q2taBcgLnIi19zrUwVhCdIlggvN6riHORK_velHcTLFK_uJhyKK0oBkJqzNqR2E-2xf8="))
			.backupEligible(true)
			.backupState(true);
	}

	public static ImmutableCredentialRecord.ImmutableCredentialRecordBuilder fullUserCredential() {
		return ImmutableCredentialRecord.builder()
			.label("label")
			.credentialId(Bytes.fromBase64("NauGCN7bZ5jEBwThcde51g"))
			.userEntityUserId(Bytes.fromBase64("vKBFhsWT3gQnn-gHdT4VXIvjDkVXVYg5w8CLGHPunMM"))
			.publicKey(ImmutablePublicKeyCose.fromBase64(
					"pQECAyYgASFYIC7DAiV_trHFPjieOxXbec7q2taBcgLnIi19zrUwVhCdIlggvN6riHORK_velHcTLFK_uJhyKK0oBkJqzNqR2E-2xf8="))
			.backupEligible(true)
			.created(Instant.now())
			.transports(Set.of(AuthenticatorTransport.BLE, AuthenticatorTransport.HYBRID))
			.signatureCount(100)
			.uvInitialized(false)
			.credentialType(PublicKeyCredentialType.PUBLIC_KEY)
			.attestationObject(new Bytes("test".getBytes()))
			.attestationClientDataJSON(new Bytes(("test").getBytes()))
			.backupState(true);
	}

	private TestCredentialRecord() {
	}

}
