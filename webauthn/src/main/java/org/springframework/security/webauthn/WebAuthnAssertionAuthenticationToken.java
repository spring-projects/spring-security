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

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.webauthn.request.WebAuthnAuthenticationRequest;

/**
 * An {@link Authentication} implementation for representing WebAuthn assertion like
 * {@link UsernamePasswordAuthenticationToken} for password authentication
 *
 * @author Yoshikazu Nojima
 */
public class WebAuthnAssertionAuthenticationToken extends AbstractAuthenticationToken {

	// ~ Instance fields
	// ================================================================================================
	private WebAuthnAuthenticationRequest credentials;


	// ~ Constructor
	// ========================================================================================================

	/**
	 * This constructor can be safely used by any code that wishes to create a
	 * <code>WebAuthnAssertionAuthenticationToken</code>, as the {@link #isAuthenticated()}
	 * will return <code>false</code>.
	 *
	 * @param credentials credential
	 */
	public WebAuthnAssertionAuthenticationToken(WebAuthnAuthenticationRequest credentials) {
		super(null);
		this.credentials = credentials;
		setAuthenticated(false);
	}

	// ~ Methods
	// ========================================================================================================

	/**
	 * Always null
	 *
	 * @return null
	 */
	@Override
	public String getPrincipal() {
		return null;
	}

	/**
	 * @return the stored WebAuthn authentication context
	 */
	@Override
	public WebAuthnAuthenticationRequest getCredentials() {
		return credentials;
	}

	/**
	 * This object can never be authenticated, call with true result in exception.
	 *
	 * @param isAuthenticated only false value allowed
	 * @throws IllegalArgumentException if isAuthenticated is true
	 */
	@Override
	public void setAuthenticated(boolean isAuthenticated) {
		if (isAuthenticated) {
			throw new IllegalArgumentException(
					"Cannot set this authenticator to trusted");
		}

		super.setAuthenticated(false);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void eraseCredentials() {
		super.eraseCredentials();
		credentials = null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof WebAuthnAssertionAuthenticationToken)) return false;
		if (!super.equals(o)) return false;

		WebAuthnAssertionAuthenticationToken that = (WebAuthnAssertionAuthenticationToken) o;

		return credentials != null ? credentials.equals(that.credentials) : that.credentials == null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int hashCode() {
		int result = super.hashCode();
		result = 31 * result + (credentials != null ? credentials.hashCode() : 0);
		return result;
	}
}
