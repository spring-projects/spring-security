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

package org.springframework.security.authentication;

import java.util.Collection;

import org.springframework.security.core.AuthenticationResult;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

/**
 * Represents a remembered <code>Authentication</code>.
 * <p>
 * A remembered <code>Authentication</code> must provide a fully valid
 * <code>Authentication</code>, including the <code>GrantedAuthority</code>s that apply.
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
public class RememberMeAuthenticationToken extends AbstractAuthenticationToken implements AuthenticationResult {

	private static final long serialVersionUID = 620L;

	private final Object principal;

	private final int keyHash;

	/**
	 * Constructor.
	 * @param key to identify if this object made by an authorised client
	 * @param principal the principal (typically a <code>UserDetails</code>)
	 * @param authorities the authorities granted to the principal
	 * @throws IllegalArgumentException if a <code>null</code> was passed
	 */
	public RememberMeAuthenticationToken(String key, Object principal,
			Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		if ((key == null) || ("".equals(key)) || (principal == null) || "".equals(principal)) {
			throw new IllegalArgumentException("Cannot pass null or empty values to constructor");
		}
		this.keyHash = key.hashCode();
		this.principal = principal;
		setAuthenticated(true);
	}

	/**
	 * Private Constructor to help in Jackson deserialization.
	 * @param keyHash hashCode of above given key.
	 * @param principal the principal (typically a <code>UserDetails</code>)
	 * @param authorities the authorities granted to the principal
	 * @since 4.2
	 */
	private RememberMeAuthenticationToken(Integer keyHash, Object principal,
			Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.keyHash = keyHash;
		this.principal = principal;
		setAuthenticated(true);
	}

	@Override
	public RememberMeAuthenticationToken withGrantedAuthorities(Collection<GrantedAuthority> authorities) {
		Assert.isTrue(isAuthenticated(), "cannot grant authorities to unauthenticated tokens");
		return new RememberMeAuthenticationToken(this.keyHash, getPrincipal(), authorities);
	}

	/**
	 * Always returns an empty <code>String</code>
	 * @return an empty String
	 */
	@Override
	public Object getCredentials() {
		return "";
	}

	public int getKeyHash() {
		return this.keyHash;
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

	@Override
	public boolean equals(Object obj) {
		if (!super.equals(obj)) {
			return false;
		}
		if (obj instanceof RememberMeAuthenticationToken other) {
			return this.getKeyHash() == other.getKeyHash();
		}
		return false;
	}

	@Override
	public int hashCode() {
		int result = super.hashCode();
		result = 31 * result + this.keyHash;
		return result;
	}

}
