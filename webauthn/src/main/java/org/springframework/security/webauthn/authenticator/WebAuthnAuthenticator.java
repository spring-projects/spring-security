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

import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import org.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;

import java.util.Objects;

/**
 * Models core authenticator information retrieved by a {@link WebAuthnUserDetailsService}
 *
 * @author Yoshikazu Nojima
 * @see WebAuthnUserDetailsService
 */
public class WebAuthnAuthenticator extends AuthenticatorImpl {

	// ~ Instance fields
	// ================================================================================================
	private String name;

	// ~ Constructor
	// ========================================================================================================

	/**
	 * Constructor
	 *
	 * @param name                   authenticator's friendly name
	 * @param attestedCredentialData attested credential data
	 * @param attestationStatement   attestation statement
	 * @param counter                counter
	 */
	public WebAuthnAuthenticator(String name, AttestedCredentialData attestedCredentialData, AttestationStatement attestationStatement, long counter) {
		super(attestedCredentialData, attestationStatement, counter);
		this.setName(name);
	}

	// ~ Methods
	// ========================================================================================================

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		if (!super.equals(o)) return false;
		WebAuthnAuthenticator that = (WebAuthnAuthenticator) o;
		return Objects.equals(name, that.name);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int hashCode() {

		return Objects.hash(super.hashCode(), name);
	}
}
