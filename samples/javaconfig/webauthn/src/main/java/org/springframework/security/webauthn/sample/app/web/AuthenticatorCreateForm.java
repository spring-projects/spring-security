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

package org.springframework.security.webauthn.sample.app.web;

import com.webauthn4j.data.AuthenticatorTransport;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.util.Set;

public class AuthenticatorCreateForm {

	@NotNull
	@Valid
	private String clientDataJSON;

	@NotNull
	@Valid
	private String attestationObject;

	private Set<AuthenticatorTransport> transports;

	@NotNull
	private String clientExtensions;

	public String getClientDataJSON() {
		return clientDataJSON;
	}

	public void setClientDataJSON(String clientDataJSON) {
		this.clientDataJSON = clientDataJSON;
	}

	public String getAttestationObject() {
		return attestationObject;
	}

	public void setAttestationObject(String attestationObject) {
		this.attestationObject = attestationObject;
	}

	public Set<AuthenticatorTransport> getTransports() {
		return transports;
	}

	public void setTransports(Set<AuthenticatorTransport> transports) {
		this.transports = transports;
	}

	public String getClientExtensions() {
		return clientExtensions;
	}

	public void setClientExtensions(String clientExtensions) {
		this.clientExtensions = clientExtensions;
	}
}
