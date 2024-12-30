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

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

/**
 * Base class for <code>Authentication</code> objects.
 * <p>
 * Implementations which use this class should be immutable.
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
public abstract class AbstractAuthenticationToken implements Authentication, CredentialsContainer {

	private final Collection<GrantedAuthority> authorities;

	private Object details;

	private boolean authenticated = false;

	/**
	 * Creates a token with the supplied array of authorities.
	 * @param authorities the collection of <tt>GrantedAuthority</tt>s for the principal
	 * represented by this authentication object.
	 */
	public AbstractAuthenticationToken(Collection<? extends GrantedAuthority> authorities) {
		if (authorities == null) {
			this.authorities = AuthorityUtils.NO_AUTHORITIES;
			return;
		}
		for (GrantedAuthority a : authorities) {
			Assert.notNull(a, "Authorities collection cannot contain any null elements");
		}
		this.authorities = Collections.unmodifiableList(new ArrayList<>(authorities));
	}

	@Override
	public Collection<GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	@Override
	public String getName() {
		if (this.getPrincipal() instanceof UserDetails userDetails) {
			return userDetails.getUsername();
		}
		if (this.getPrincipal() instanceof AuthenticatedPrincipal authenticatedPrincipal) {
			return authenticatedPrincipal.getName();
		}
		if (this.getPrincipal() instanceof Principal principal) {
			return principal.getName();
		}
		return (this.getPrincipal() == null) ? "" : this.getPrincipal().toString();
	}

	@Override
	public boolean isAuthenticated() {
		return this.authenticated;
	}

	@Override
	public void setAuthenticated(boolean authenticated) {
		this.authenticated = authenticated;
	}

	@Override
	public Object getDetails() {
		return this.details;
	}

	public void setDetails(Object details) {
		this.details = details;
	}

	/**
	 * Checks the {@code credentials}, {@code principal} and {@code details} objects,
	 * invoking the {@code eraseCredentials} method on any which implement
	 * {@link CredentialsContainer}.
	 */
	@Override
	public void eraseCredentials() {
		eraseSecret(getCredentials());
		eraseSecret(getPrincipal());
		eraseSecret(this.details);
	}

	private void eraseSecret(Object secret) {
		if (secret instanceof CredentialsContainer container) {
			container.eraseCredentials();
		}
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof AbstractAuthenticationToken test)) {
			return false;
		}
		if (!this.authorities.equals(test.authorities)) {
			return false;
		}
		if ((this.details == null) && (test.getDetails() != null)) {
			return false;
		}
		if ((this.details != null) && (test.getDetails() == null)) {
			return false;
		}
		if ((this.details != null) && (!this.details.equals(test.getDetails()))) {
			return false;
		}
		if ((this.getCredentials() == null) && (test.getCredentials() != null)) {
			return false;
		}
		if ((this.getCredentials() != null) && !this.getCredentials().equals(test.getCredentials())) {
			return false;
		}
		if (this.getPrincipal() == null && test.getPrincipal() != null) {
			return false;
		}
		if (this.getPrincipal() != null && !this.getPrincipal().equals(test.getPrincipal())) {
			return false;
		}
		return this.isAuthenticated() == test.isAuthenticated();
	}

	@Override
	public int hashCode() {
		int code = 31;
		for (GrantedAuthority authority : this.authorities) {
			code ^= authority.hashCode();
		}
		if (this.getPrincipal() != null) {
			code ^= this.getPrincipal().hashCode();
		}
		if (this.getCredentials() != null) {
			code ^= this.getCredentials().hashCode();
		}
		if (this.getDetails() != null) {
			code ^= this.getDetails().hashCode();
		}
		if (this.isAuthenticated()) {
			code ^= -37;
		}
		return code;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(getClass().getSimpleName()).append(" [");
		sb.append("Principal=").append(getPrincipal()).append(", ");
		sb.append("Credentials=[PROTECTED], ");
		sb.append("Authenticated=").append(isAuthenticated()).append(", ");
		sb.append("Details=").append(getDetails()).append(", ");
		sb.append("Granted Authorities=").append(this.authorities);
		sb.append("]");
		return sb.toString();
	}

}
