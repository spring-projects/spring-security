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

package org.springframework.security.webauthn;

import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.ArrayUtil;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;


/**
 * Internal data transfer object to represent WebAuthn authentication request
 *
 * @author Yoshikazu Nojima
 */
public class WebAuthnAuthenticationData implements Serializable {

	//~ Instance fields
	// ================================================================================================
	// user inputs
	private final byte[] credentialId;
	private final byte[] clientDataJSON;
	private final byte[] authenticatorData;
	private final byte[] signature;
	private final String clientExtensionsJSON;

	private final ServerProperty serverProperty;
	private final boolean userVerificationRequired;
	private final boolean userPresenceRequired;
	private final List<String> expectedAuthenticationExtensionIds;

	@SuppressWarnings("squid:S00107")
	public WebAuthnAuthenticationData(
			byte[] credentialId,
			byte[] clientDataJSON,
			byte[] authenticatorData,
			byte[] signature,
			String clientExtensionsJSON,
			ServerProperty serverProperty,
			boolean userVerificationRequired,
			boolean userPresenceRequired,
			List<String> expectedAuthenticationExtensionIds) {

		this.credentialId = ArrayUtil.clone(credentialId);
		this.clientDataJSON = ArrayUtil.clone(clientDataJSON);
		this.authenticatorData = ArrayUtil.clone(authenticatorData);
		this.signature = ArrayUtil.clone(signature);
		this.clientExtensionsJSON = clientExtensionsJSON;
		this.serverProperty = serverProperty;
		this.userVerificationRequired = userVerificationRequired;
		this.userPresenceRequired = userPresenceRequired;
		this.expectedAuthenticationExtensionIds = Collections.unmodifiableList(expectedAuthenticationExtensionIds);
	}

	@SuppressWarnings("squid:S00107")
	public WebAuthnAuthenticationData(
			byte[] credentialId,
			byte[] clientDataJSON,
			byte[] authenticatorData,
			byte[] signature,
			String clientExtensionsJSON,
			ServerProperty serverProperty,
			boolean userVerificationRequired,
			List<String> expectedAuthenticationExtensionIds) {

		this(
				credentialId,
				clientDataJSON,
				authenticatorData,
				signature,
				clientExtensionsJSON,
				serverProperty,
				userVerificationRequired,
				true,
				expectedAuthenticationExtensionIds
		);
	}

	public byte[] getCredentialId() {
		return ArrayUtil.clone(credentialId);
	}

	public byte[] getClientDataJSON() {
		return ArrayUtil.clone(clientDataJSON);
	}

	public byte[] getAuthenticatorData() {
		return ArrayUtil.clone(authenticatorData);
	}

	public byte[] getSignature() {
		return ArrayUtil.clone(signature);
	}

	public String getClientExtensionsJSON() {
		return clientExtensionsJSON;
	}

	public ServerProperty getServerProperty() {
		return serverProperty;
	}

	public boolean isUserVerificationRequired() {
		return userVerificationRequired;
	}

	public boolean isUserPresenceRequired() {
		return userPresenceRequired;
	}

	public List<String> getExpectedAuthenticationExtensionIds() {
		return expectedAuthenticationExtensionIds;
	}


	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		WebAuthnAuthenticationData that = (WebAuthnAuthenticationData) o;
		return userVerificationRequired == that.userVerificationRequired &&
				userPresenceRequired == that.userPresenceRequired &&
				Arrays.equals(credentialId, that.credentialId) &&
				Arrays.equals(clientDataJSON, that.clientDataJSON) &&
				Arrays.equals(authenticatorData, that.authenticatorData) &&
				Arrays.equals(signature, that.signature) &&
				Objects.equals(clientExtensionsJSON, that.clientExtensionsJSON) &&
				Objects.equals(serverProperty, that.serverProperty) &&
				Objects.equals(expectedAuthenticationExtensionIds, that.expectedAuthenticationExtensionIds);
	}

	@Override
	public int hashCode() {
		int result = Objects.hash(clientExtensionsJSON, serverProperty, userVerificationRequired, userPresenceRequired, expectedAuthenticationExtensionIds);
		result = 31 * result + Arrays.hashCode(credentialId);
		result = 31 * result + Arrays.hashCode(clientDataJSON);
		result = 31 * result + Arrays.hashCode(authenticatorData);
		result = 31 * result + Arrays.hashCode(signature);
		return result;
	}
}
