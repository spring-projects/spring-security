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

package org.springframework.security.web.webauthn.management;

import org.springframework.security.web.webauthn.api.AuthenticatorAttestationResponse;
import org.springframework.security.web.webauthn.api.PublicKeyCredential;
import org.springframework.util.Assert;

/**
 * Submitted by a client to request registration of a new credential.
 *
 * @author Rob Winch
 * @since 6.4
 */
public class RelyingPartyPublicKey {

	private final PublicKeyCredential<AuthenticatorAttestationResponse> credential;

	private final String label;

	/**
	 * Creates a new instance.
	 * @param credential the credential
	 * @param label a human readable label that will be associated to the credential
	 */
	public RelyingPartyPublicKey(PublicKeyCredential<AuthenticatorAttestationResponse> credential, String label) {
		Assert.notNull(credential, "credential cannot be null");
		Assert.notNull(label, "label cannot be null");
		this.credential = credential;
		this.label = label;
	}

	public PublicKeyCredential<AuthenticatorAttestationResponse> getCredential() {
		return this.credential;
	}

	public String getLabel() {
		return this.label;
	}

}
