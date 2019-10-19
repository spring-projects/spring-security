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

import java.util.Collections;
import java.util.List;
import java.util.Set;

public class WebAuthnRegistrationData {

	private final byte[] clientDataJSON;
	private final byte[] attestationObject;
	private final Set<String> transports;
	private final String clientExtensionsJSON;

	private final ServerProperty serverProperty;
	private final List<String> expectedRegistrationExtensionIds;

	public WebAuthnRegistrationData(byte[] clientDataJSON, byte[] attestationObject, Set<String> transports, String clientExtensionsJSON,
									ServerProperty serverProperty,
									List<String> expectedRegistrationExtensionIds) {
		this.clientDataJSON = ArrayUtil.clone(clientDataJSON);
		this.attestationObject = ArrayUtil.clone(attestationObject);
		this.transports = transports == null ? null : Collections.unmodifiableSet(transports);
		this.clientExtensionsJSON = clientExtensionsJSON;
		this.serverProperty = serverProperty;
		this.expectedRegistrationExtensionIds = expectedRegistrationExtensionIds == null ? null : Collections.unmodifiableList(expectedRegistrationExtensionIds);
	}

	public byte[] getClientDataJSON() {
		return ArrayUtil.clone(clientDataJSON);
	}

	public byte[] getAttestationObject() {
		return ArrayUtil.clone(attestationObject);
	}

	public Set<String> getTransports() {
		return transports;
	}

	public String getClientExtensionsJSON() {
		return clientExtensionsJSON;
	}

	public ServerProperty getServerProperty() {
		return serverProperty;
	}

	public List<String> getExpectedRegistrationExtensionIds() {
		return expectedRegistrationExtensionIds;
	}
}
