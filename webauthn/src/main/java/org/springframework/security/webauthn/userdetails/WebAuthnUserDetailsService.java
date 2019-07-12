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

package org.springframework.security.webauthn.userdetails;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.webauthn.exception.CredentialIdNotFoundException;

/**
 * Specialized {@link UserDetailsService} for WebAuthn
 *
 * @author Yoshikazu Nojima
 */
public interface WebAuthnUserDetailsService {

	/**
	 * Locates a user based on the username.
	 *
	 * @param username the username identifying the user whose data is required
	 * @return a fully populated {@link WebAuthnUserDetails} instance  (never <code>null</code>)
	 * @throws UsernameNotFoundException if the user could not be found
	 */
	@SuppressWarnings("squid:RedundantThrowsDeclarationCheck")
	WebAuthnUserDetails loadWebAuthnUserByUsername(String username) throws UsernameNotFoundException;

	/**
	 * Locates a user based on the credentialId.
	 *
	 * @param credentialId credentialId
	 * @return fully populated {@link WebAuthnUserDetails} instance (never <code>null</code>),
	 * which must returns the authenticator in getAuthenticators result.
	 * @throws CredentialIdNotFoundException if the authenticator could not be found
	 */
	@SuppressWarnings("squid:RedundantThrowsDeclarationCheck")
	WebAuthnUserDetails loadWebAuthnUserByCredentialId(byte[] credentialId) throws CredentialIdNotFoundException;
}
