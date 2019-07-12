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

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.webauthn.authenticator.WebAuthnAuthenticator;

import java.io.Serializable;
import java.util.Collection;

/**
 * An extended {@link UserDetails} interface for WebAuthn
 *
 * @author Yoshikazu Nojima
 */
public interface WebAuthnUserDetails extends Serializable {
	// ~ Methods
	// ========================================================================================================

	/**
	 * Returns the authorities granted to the user. Cannot return <code>null</code>.
	 *
	 * @return the authorities, sorted by natural key (never <code>null</code>)
	 */
	Collection<? extends GrantedAuthority> getAuthorities();

	/**
	 * Returns the userHandle that identifies the user. Cannot return <code>null</code>.
	 *
	 * @return the userHandle (never <code>null</code>)
	 */
	byte[] getUserHandle();

	/**
	 * Returns the username used to authenticate the user. Cannot return <code>null</code>.
	 *
	 * @return the username (never <code>null</code>)
	 */
	String getUsername();

	/**
	 * Returns the authenticators used to authenticate the user.
	 *
	 * @return the authenticators
	 */
	@SuppressWarnings("squid:S1452")
	Collection<? extends WebAuthnAuthenticator> getAuthenticators();

	/**
	 * Indicates whether the user's account has expired. An expired account cannot be
	 * authenticated.
	 *
	 * @return <code>true</code> if the user's account is valid (ie non-expired),
	 * <code>false</code> if no longer valid (ie expired)
	 */
	boolean isAccountNonExpired();

	/**
	 * Indicates whether the user is locked or unlocked. A locked user cannot be
	 * authenticated.
	 *
	 * @return <code>true</code> if the user is not locked, <code>false</code> otherwise
	 */
	boolean isAccountNonLocked();

	/**
	 * Indicates whether the user's credentials (password) has expired. Expired
	 * credentials prevent authentication.
	 *
	 * @return <code>true</code> if the user's credentials are valid (ie non-expired),
	 * <code>false</code> if no longer valid (ie expired)
	 */
	boolean isCredentialsNonExpired();

	/**
	 * Indicates whether the user is enabled or disabled. A disabled user cannot be
	 * authenticated.
	 *
	 * @return <code>true</code> if the user is enabled, <code>false</code> otherwise
	 */
	boolean isEnabled();

}
