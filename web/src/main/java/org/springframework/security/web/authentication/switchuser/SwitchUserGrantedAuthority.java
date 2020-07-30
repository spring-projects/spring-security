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

package org.springframework.security.web.authentication.switchuser;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

/**
 * Custom {@code GrantedAuthority} used by
 * {@link org.springframework.security.web.authentication.switchuser.SwitchUserFilter}
 * <p>
 * Stores the {@code Authentication} object of the original user to be used later when
 * 'exiting' from a user switch.
 *
 * @author Mark St.Godard
 * @see org.springframework.security.web.authentication.switchuser.SwitchUserFilter
 */
public final class SwitchUserGrantedAuthority implements GrantedAuthority {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final String role;

	private final Authentication source;

	public SwitchUserGrantedAuthority(String role, Authentication source) {
		Assert.notNull(role, "role cannot be null");
		Assert.notNull(source, "source cannot be null");
		this.role = role;
		this.source = source;
	}

	/**
	 * Returns the original user associated with a successful user switch.
	 * @return The original <code>Authentication</code> object of the switched user.
	 */
	public Authentication getSource() {
		return this.source;
	}

	@Override
	public String getAuthority() {
		return this.role;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj instanceof SwitchUserGrantedAuthority) {
			SwitchUserGrantedAuthority swa = (SwitchUserGrantedAuthority) obj;
			return this.role.equals(swa.role) && this.source.equals(swa.source);
		}
		return false;
	}

	@Override
	public int hashCode() {
		int result = this.role.hashCode();
		result = 31 * result + this.source.hashCode();
		return result;
	}

	@Override
	public String toString() {
		return "Switch User Authority [" + this.role + "," + this.source + "]";
	}

}
