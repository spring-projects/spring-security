/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.cas.authentication;

import java.io.Serializable;
import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

/**
 * An {@link org.springframework.security.core.Authentication} implementation that is
 * designed to process CAS service ticket.
 *
 * @author Hal Deadman
 * @since 6.1
 */
public class CasServiceTicketAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final CasUserAgentType userAgentType;

	private Object credentials;

	/**
	 * This constructor can be safely used by any code that wishes to create a
	 * <code>CasServiceTicketAuthenticationToken</code>, as the {@link #isAuthenticated()}
	 * will return <code>false</code>.
	 *
	 */
	public CasServiceTicketAuthenticationToken(CasUserAgentType userAgentType, Object credentials) {
		super(null);
		this.userAgentType = userAgentType;
		this.credentials = credentials;
		setAuthenticated(false);
	}

	/**
	 * This constructor should only be used by <code>AuthenticationManager</code> or
	 * <code>AuthenticationProvider</code> implementations that are satisfied with
	 * producing a trusted (i.e. {@link #isAuthenticated()} = <code>true</code>)
	 * authentication token.
	 * @param userAgentType
	 * @param credentials
	 * @param authorities
	 */
	public CasServiceTicketAuthenticationToken(CasUserAgentType userAgentType, Object credentials,
			Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.userAgentType = userAgentType;
		this.credentials = credentials;
		super.setAuthenticated(true); // must use super, as we override
	}

	/**
	 * This factory method can be safely used by any code that wishes to create a
	 * unauthenticated <code>CasServiceTicketAuthenticationToken</code>.
	 * @param casUserAgentType
	 * @param credentials
	 * @return CasServiceTicketAuthenticationToken with false isAuthenticated() result
	 *
	 */
	public static CasServiceTicketAuthenticationToken unauthenticated(CasUserAgentType casUserAgentType,
			Object credentials) {
		return new CasServiceTicketAuthenticationToken(casUserAgentType, credentials);
	}

	/**
	 * This factory method can be safely used by any code that wishes to create a
	 * authenticated <code>CasServiceTicketAuthenticationToken</code>.
	 * @param casUserAgentType
	 * @param credentials
	 * @return CasServiceTicketAuthenticationToken with true isAuthenticated() result
	 *
	 */
	public static CasServiceTicketAuthenticationToken authenticated(CasUserAgentType casUserAgentType,
			Object credentials, Collection<? extends GrantedAuthority> authorities) {
		return new CasServiceTicketAuthenticationToken(casUserAgentType, credentials, authorities);
	}

	@Override
	public Object getCredentials() {
		return this.credentials;
	}

	@Override
	public Object getPrincipal() {
		return this.userAgentType;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		Assert.isTrue(!isAuthenticated,
				"Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
		super.setAuthenticated(false);
	}

	@Override
	public void eraseCredentials() {
		super.eraseCredentials();
		this.credentials = null;
	}

	public enum CasUserAgentType implements Serializable {

		CAS_STATELESS_IDENTIFIER("_cas_stateless_"), CAS_STATEFUL_IDENTIFIER("_cas_stateful_");
		private String value;

		public String getValue() {
			return this.value;
		}

		CasUserAgentType(String value) {
			this.value = value;
		}

	}

}
