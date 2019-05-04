/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.webauthn.options;


import com.webauthn4j.data.*;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.util.CollectionUtil;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;

/**
 * Options for WebAuthn attestation generation
 */
@SuppressWarnings("common-java:DuplicatedBlocks")
public class AttestationOptions implements Serializable {

	// ~ Instance fields
	// ================================================================================================

	private PublicKeyCredentialRpEntity rp;
	private PublicKeyCredentialUserEntity user;
	private Challenge challenge;
	private List<PublicKeyCredentialParameters> pubKeyCredParams;
	private Long timeout;
	private List<PublicKeyCredentialDescriptor> excludeCredentials;
	private AuthenticatorSelectionCriteria authenticatorSelection;
	private AttestationConveyancePreference attestation;
	private AuthenticationExtensionsClientInputs extensions;

	// ~ Constructors
	// ===================================================================================================

	public AttestationOptions(
			PublicKeyCredentialRpEntity rp,
			PublicKeyCredentialUserEntity user,
			Challenge challenge,
			List<PublicKeyCredentialParameters> pubKeyCredParams,
			Long timeout,
			List<PublicKeyCredentialDescriptor> excludeCredentials,
			AuthenticatorSelectionCriteria authenticatorSelection,
			AttestationConveyancePreference attestation,
			AuthenticationExtensionsClientInputs extensions) {
		this.rp = rp;
		this.user = user;
		this.challenge = challenge;
		this.pubKeyCredParams = CollectionUtil.unmodifiableList(pubKeyCredParams);
		this.timeout = timeout;
		this.excludeCredentials = CollectionUtil.unmodifiableList(excludeCredentials);
		this.authenticatorSelection = authenticatorSelection;
		this.attestation = attestation;
		this.extensions = extensions;
	}

	/**
	 * Returns PublicKeyCredentialRpEntity
	 *
	 * @return PublicKeyCredentialRpEntity
	 */
	public PublicKeyCredentialRpEntity getRp() {
		return rp;
	}

	/**
	 * If authenticated, returns {@link PublicKeyCredentialUserEntity}
	 * Otherwise returns null
	 *
	 * @return {@link PublicKeyCredentialUserEntity}
	 */
	public PublicKeyCredentialUserEntity getUser() {
		return user;
	}

	/**
	 * Returns {@link Challenge}
	 *
	 * @return {@link Challenge}
	 */
	public Challenge getChallenge() {
		return challenge;
	}

	public List<PublicKeyCredentialParameters> getPubKeyCredParams() {
		return pubKeyCredParams;
	}

	public Long getTimeout() {
		return timeout;
	}

	public List<PublicKeyCredentialDescriptor> getExcludeCredentials() {
		return excludeCredentials;
	}

	public AuthenticatorSelectionCriteria getAuthenticatorSelection() {
		return authenticatorSelection;
	}

	public AttestationConveyancePreference getAttestation() {
		return attestation;
	}

	public AuthenticationExtensionsClientInputs getExtensions() {
		return extensions;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		AttestationOptions that = (AttestationOptions) o;
		return Objects.equals(rp, that.rp) &&
				Objects.equals(user, that.user) &&
				Objects.equals(challenge, that.challenge) &&
				Objects.equals(pubKeyCredParams, that.pubKeyCredParams) &&
				Objects.equals(timeout, that.timeout) &&
				Objects.equals(excludeCredentials, that.excludeCredentials) &&
				Objects.equals(authenticatorSelection, that.authenticatorSelection) &&
				attestation == that.attestation &&
				Objects.equals(extensions, that.extensions);
	}

	@Override
	public int hashCode() {
		return Objects.hash(rp, user, challenge, pubKeyCredParams, timeout, excludeCredentials, authenticatorSelection, attestation, extensions);
	}
}
