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

/**
 * The <a href=
 * "https://www.w3.org/TR/webauthn-3/#iface-authenticatorresponse">AuthenticatorResponse</a>
 * represents <a href="https://www.w3.org/TR/webauthn-3/#authenticator">Authenticators</a>
 * respond to <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a>
 * requests.
 *
 * @author Rob Winch
 * @since 6.4
 */
public abstract class AuthenticatorResponse {

	private final Bytes clientDataJSON;

	/**
	 * Creates a new instance
	 * @param clientDataJSON the {@link #getClientDataJSON()}
	 */
	AuthenticatorResponse(Bytes clientDataJSON) {
		this.clientDataJSON = clientDataJSON;
	}

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#dom-authenticatorresponse-clientdatajson">clientDataJSON</a>
	 * contains a JSON-compatible serialization of the client data, the hash of which is
	 * passed to the authenticator by the client in its call to either create() or get()
	 * (i.e., the client data itself is not sent to the authenticator).
	 * @return the client data JSON
	 */
	public Bytes getClientDataJSON() {
		return this.clientDataJSON;
	}

}
