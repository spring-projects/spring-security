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

package org.springframework.security.webauthn.authenticator;


import com.webauthn4j.util.ArrayUtil;

import java.util.Arrays;
import java.util.Objects;
import java.util.Set;

public class WebAuthnAuthenticatorImpl implements WebAuthnAuthenticator {

	// ~ Instance fields
	// ================================================================================================
	private byte[] credentialId;
	private String name;
	private byte[] attestationObject;
	private long counter;
	private Set<WebAuthnAuthenticatorTransport> transports;
	private String clientExtensions;

	// ~ Constructor
	// ========================================================================================================

	/**
	 * Constructor
	 *
	 * @param credentialId      credential id
	 * @param name              authenticator's friendly name
	 * @param attestationObject attestation object
	 * @param counter           counter
	 * @param transports        transports
	 */
	public WebAuthnAuthenticatorImpl(
			byte[] credentialId,
			String name,
			byte[] attestationObject,
			long counter,
			Set<WebAuthnAuthenticatorTransport> transports,
			String clientExtensions) {
		this.credentialId = credentialId;
		this.name = name;
		this.attestationObject = ArrayUtil.clone(attestationObject);
		this.counter = counter;
		this.transports = transports;
		this.clientExtensions = clientExtensions;
	}

	// ~ Methods
	// ========================================================================================================

	@Override
	public byte[] getCredentialId() {
		return credentialId;
	}

	public String getName() {
		return name;
	}

	@Override
	public byte[] getAttestationObject() {
		return attestationObject;
	}

	public long getCounter() {
		return counter;
	}

	@Override
	public void setCounter(long counter) {
		this.counter = counter;
	}

	@Override
	public Set<WebAuthnAuthenticatorTransport> getTransports() {
		return transports;
	}

	@Override
	public String getClientExtensions() {
		return clientExtensions;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		WebAuthnAuthenticatorImpl that = (WebAuthnAuthenticatorImpl) o;
		return counter == that.counter &&
				Arrays.equals(credentialId, that.credentialId) &&
				Objects.equals(name, that.name) &&
				Arrays.equals(attestationObject, that.attestationObject) &&
				Objects.equals(transports, that.transports) &&
				Objects.equals(clientExtensions, that.clientExtensions);
	}

	@Override
	public int hashCode() {
		int result = Objects.hash(name, counter, transports, clientExtensions);
		result = 31 * result + Arrays.hashCode(credentialId);
		result = 31 * result + Arrays.hashCode(attestationObject);
		return result;
	}
}
