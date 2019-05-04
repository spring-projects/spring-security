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

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.util.ArrayUtil;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.List;

/**
 * A {@link WebAuthnUserDetails} implementation
 *
 * @author Yoshikazu Nojima
 */
@SuppressWarnings("squid:S2160")
public class WebAuthnUserDetailsImpl extends User implements WebAuthnUserDetails {

	// ~ Instance fields
	// ================================================================================================
	private boolean singleFactorAuthenticationAllowed = false;
	private byte[] userHandle;
	private List<Authenticator> authenticators;

	public WebAuthnUserDetailsImpl(
			byte[] userHandle, String username, String password, List<Authenticator> authenticators,
			Collection<? extends GrantedAuthority> authorities) {
		this(userHandle, username, password, authenticators, false, authorities);
	}

	public WebAuthnUserDetailsImpl(
			byte[] userHandle, String username, String password, List<Authenticator> authenticators,
			boolean singleFactorAuthenticationAllowed, Collection<? extends GrantedAuthority> authorities) {
		this(userHandle, username, password, authenticators, singleFactorAuthenticationAllowed,
				true, true, true, true,
				authorities);
	}

	@SuppressWarnings("squid:S00107")
	public WebAuthnUserDetailsImpl(
			byte[] userHandle, String username, String password, List<Authenticator> authenticators,
			boolean singleFactorAuthenticationAllowed, boolean enabled, boolean accountNonExpired,
			boolean credentialsNonExpired, boolean accountNonLocked,
			Collection<? extends GrantedAuthority> authorities) {
		super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
		this.userHandle = userHandle;
		this.authenticators = authenticators;
		this.singleFactorAuthenticationAllowed = singleFactorAuthenticationAllowed;
	}

	@Override
	public byte[] getUserHandle() {
		return ArrayUtil.clone(userHandle);
	}

	@Override
	public List<Authenticator> getAuthenticators() {
		return this.authenticators;
	}

	@Override
	public boolean isSingleFactorAuthenticationAllowed() {
		return singleFactorAuthenticationAllowed;
	}

	@Override
	public void setSingleFactorAuthenticationAllowed(boolean singleFactorAuthenticationAllowed) {
		this.singleFactorAuthenticationAllowed = singleFactorAuthenticationAllowed;
	}


}
