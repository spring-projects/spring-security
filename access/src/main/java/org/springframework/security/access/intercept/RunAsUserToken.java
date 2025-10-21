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

package org.springframework.security.access.intercept;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * An immutable {@link org.springframework.security.core.Authentication} implementation
 * that supports {@link RunAsManagerImpl}.
 *
 * @author Ben Alex
 * @deprecated Authentication is now separated from authorization in Spring Security. This
 * class is only used by now-deprecated components. There is not yet an equivalent
 * replacement in Spring Security.
 */
@Deprecated
public class RunAsUserToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = 620L;

	private final Class<? extends Authentication> originalAuthentication;

	private final Object credentials;

	private final Object principal;

	private final int keyHash;

	public RunAsUserToken(String key, Object principal, Object credentials,
			Collection<? extends GrantedAuthority> authorities,
			Class<? extends Authentication> originalAuthentication) {
		super(authorities);
		this.keyHash = key.hashCode();
		this.principal = principal;
		this.credentials = credentials;
		this.originalAuthentication = originalAuthentication;
		setAuthenticated(true);
	}

	@Override
	public Object getCredentials() {
		return this.credentials;
	}

	public int getKeyHash() {
		return this.keyHash;
	}

	public Class<? extends Authentication> getOriginalAuthentication() {
		return this.originalAuthentication;
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder(super.toString());
		String className = (this.originalAuthentication != null) ? this.originalAuthentication.getName() : null;
		sb.append("; Original Class: ").append(className);
		return sb.toString();
	}

}
