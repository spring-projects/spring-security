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

package org.springframework.security.authentication.jaas;

import java.security.Principal;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

/**
 * {@code GrantedAuthority} which, in addition to the assigned role, holds the principal
 * that an {@link AuthorityGranter} used as a reason to grant this authority.
 *
 * @author Ray Krueger
 * @see AuthorityGranter
 */
public final class JaasGrantedAuthority implements GrantedAuthority {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final String role;

	private final Principal principal;

	public JaasGrantedAuthority(String role, Principal principal) {
		Assert.notNull(role, "role cannot be null");
		Assert.notNull(principal, "principal cannot be null");
		this.role = role;
		this.principal = principal;
	}

	public Principal getPrincipal() {
		return principal;
	}

	@Override
	public String getAuthority() {
		return role;
	}

	@Override
	public int hashCode() {
		int result = this.principal.hashCode();
		result = 31 * result + this.role.hashCode();
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}

		if (obj instanceof JaasGrantedAuthority) {
			JaasGrantedAuthority jga = (JaasGrantedAuthority) obj;
			return this.role.equals(jga.role) && this.principal.equals(jga.principal);
		}

		return false;
	}

	@Override
	public String toString() {
		return "Jaas Authority [" + role + "," + principal + "]";
	}

}
