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

import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.util.Assert;

/**
 * Contains the information necessary to register a new Credential.
 *
 * @author Rob Winch
 * @since 6.4
 * @see Webauthn4JRelyingPartyOperations#registerCredential(RelyingPartyRegistrationRequest)
 */
public class ImmutableRelyingPartyRegistrationRequest implements RelyingPartyRegistrationRequest {

	private final PublicKeyCredentialCreationOptions options;

	private final RelyingPartyPublicKey publicKey;

	/**
	 * Creates a new instance.
	 * @param options the {@link PublicKeyCredentialCreationOptions} that were saved when
	 * {@link WebAuthnRelyingPartyOperations#createCredentialRequestOptions(PublicKeyCredentialRequestOptionsRequest)}
	 * was called.
	 * @param publicKey this is submitted by the client and if validated stored.
	 */
	public ImmutableRelyingPartyRegistrationRequest(PublicKeyCredentialCreationOptions options,
			RelyingPartyPublicKey publicKey) {
		Assert.notNull(options, "options cannot be null");
		Assert.notNull(publicKey, "publicKey cannot be null");
		this.options = options;
		this.publicKey = publicKey;
	}

	@Override
	public PublicKeyCredentialCreationOptions getCreationOptions() {
		return this.options;
	}

	@Override
	public RelyingPartyPublicKey getPublicKey() {
		return this.publicKey;
	}

}
