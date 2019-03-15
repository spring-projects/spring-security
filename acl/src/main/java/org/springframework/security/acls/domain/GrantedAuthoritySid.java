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
package org.springframework.security.acls.domain;

import org.springframework.security.acls.model.Sid;
import org.springframework.security.core.GrantedAuthority;

import org.springframework.util.Assert;

/**
 * Represents a <code>GrantedAuthority</code> as a <code>Sid</code>.
 * <p>
 * This is a basic implementation that simply uses the <code>String</code>-based principal
 * for <code>Sid</code> comparison. More complex principal objects may wish to provide an
 * alternative <code>Sid</code> implementation that uses some other identifier.
 * </p>
 *
 * @author Ben Alex
 */
public class GrantedAuthoritySid implements Sid {
	// ~ Instance fields
	// ================================================================================================

	private final String grantedAuthority;

	// ~ Constructors
	// ===================================================================================================

	public GrantedAuthoritySid(String grantedAuthority) {
		Assert.hasText(grantedAuthority, "GrantedAuthority required");
		this.grantedAuthority = grantedAuthority;
	}

	public GrantedAuthoritySid(GrantedAuthority grantedAuthority) {
		Assert.notNull(grantedAuthority, "GrantedAuthority required");
		Assert.notNull(
				grantedAuthority.getAuthority(),
				"This Sid is only compatible with GrantedAuthoritys that provide a non-null getAuthority()");
		this.grantedAuthority = grantedAuthority.getAuthority();
	}

	// ~ Methods
	// ========================================================================================================

	public boolean equals(Object object) {
		if ((object == null) || !(object instanceof GrantedAuthoritySid)) {
			return false;
		}

		// Delegate to getGrantedAuthority() to perform actual comparison (both should be
		// identical)
		return ((GrantedAuthoritySid) object).getGrantedAuthority().equals(
				this.getGrantedAuthority());
	}

	public int hashCode() {
		return this.getGrantedAuthority().hashCode();
	}

	public String getGrantedAuthority() {
		return grantedAuthority;
	}

	public String toString() {
		return "GrantedAuthoritySid[" + this.grantedAuthority + "]";
	}
}
