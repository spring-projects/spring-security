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

package org.springframework.security.ldap.userdetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.naming.Name;

import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.ldap.ppolicy.PasswordPolicyData;
import org.springframework.util.Assert;

/**
 * A UserDetails implementation which is used internally by the Ldap services. It also
 * contains the user's distinguished name and a set of attributes that have been retrieved
 * from the Ldap server.
 * <p>
 * An instance may be created as the result of a search, or when user information is
 * retrieved during authentication.
 * <p>
 * An instance of this class will be used by the <tt>LdapAuthenticationProvider</tt> to
 * construct the final user details object that it returns.
 * <p>
 * The {@code equals} and {@code hashcode} methods are implemented using the {@code Dn}
 * property and do not consider additional state, so it is not possible two store two
 * instances with the same DN in the same set, or use them as keys in a map.
 *
 * @author Luke Taylor
 */
public class LdapUserDetailsImpl implements LdapUserDetails, PasswordPolicyData {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private String dn;

	private String password;

	private String username;

	private Collection<GrantedAuthority> authorities = AuthorityUtils.NO_AUTHORITIES;

	private boolean accountNonExpired = true;

	private boolean accountNonLocked = true;

	private boolean credentialsNonExpired = true;

	private boolean enabled = true;

	// PPolicy data
	private int timeBeforeExpiration = Integer.MAX_VALUE;

	private int graceLoginsRemaining = Integer.MAX_VALUE;

	protected LdapUserDetailsImpl() {
	}

	@Override
	public Collection<GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	@Override
	public String getDn() {
		return this.dn;
	}

	@Override
	public String getPassword() {
		return this.password;
	}

	@Override
	public String getUsername() {
		return this.username;
	}

	@Override
	public boolean isAccountNonExpired() {
		return this.accountNonExpired;
	}

	@Override
	public boolean isAccountNonLocked() {
		return this.accountNonLocked;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return this.credentialsNonExpired;
	}

	@Override
	public boolean isEnabled() {
		return this.enabled;
	}

	@Override
	public void eraseCredentials() {
		this.password = null;
	}

	@Override
	public int getTimeBeforeExpiration() {
		return this.timeBeforeExpiration;
	}

	@Override
	public int getGraceLoginsRemaining() {
		return this.graceLoginsRemaining;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof LdapUserDetailsImpl) {
			return this.dn.equals(((LdapUserDetailsImpl) obj).dn);
		}
		return false;
	}

	@Override
	public int hashCode() {
		return this.dn.hashCode();
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(super.toString()).append(": ");
		sb.append("Dn: ").append(this.dn).append("; ");
		sb.append("Username: ").append(this.username).append("; ");
		sb.append("Password: [PROTECTED]; ");
		sb.append("Enabled: ").append(this.enabled).append("; ");
		sb.append("AccountNonExpired: ").append(this.accountNonExpired).append("; ");
		sb.append("CredentialsNonExpired: ").append(this.credentialsNonExpired).append("; ");
		sb.append("AccountNonLocked: ").append(this.accountNonLocked).append("; ");

		if (this.getAuthorities() != null && !this.getAuthorities().isEmpty()) {
			sb.append("Granted Authorities: ");
			boolean first = true;

			for (Object authority : this.getAuthorities()) {
				if (first) {
					first = false;
				}
				else {
					sb.append(", ");
				}

				sb.append(authority.toString());
			}
		}
		else {
			sb.append("Not granted any authorities");
		}

		return sb.toString();
	}

	/**
	 * Variation of essence pattern. Used to create mutable intermediate object
	 */
	public static class Essence {

		protected LdapUserDetailsImpl instance = createTarget();

		private List<GrantedAuthority> mutableAuthorities = new ArrayList<>();

		public Essence() {
		}

		public Essence(DirContextOperations ctx) {
			setDn(ctx.getDn());
		}

		public Essence(LdapUserDetails copyMe) {
			setDn(copyMe.getDn());
			setUsername(copyMe.getUsername());
			setPassword(copyMe.getPassword());
			setEnabled(copyMe.isEnabled());
			setAccountNonExpired(copyMe.isAccountNonExpired());
			setCredentialsNonExpired(copyMe.isCredentialsNonExpired());
			setAccountNonLocked(copyMe.isAccountNonLocked());
			setAuthorities(copyMe.getAuthorities());
		}

		protected LdapUserDetailsImpl createTarget() {
			return new LdapUserDetailsImpl();
		}

		/**
		 * Adds the authority to the list, unless it is already there, in which case it is
		 * ignored
		 */
		public void addAuthority(GrantedAuthority a) {
			if (!hasAuthority(a)) {
				this.mutableAuthorities.add(a);
			}
		}

		private boolean hasAuthority(GrantedAuthority a) {
			for (GrantedAuthority authority : this.mutableAuthorities) {
				if (authority.equals(a)) {
					return true;
				}
			}
			return false;
		}

		public LdapUserDetails createUserDetails() {
			Assert.notNull(this.instance, "Essence can only be used to create a single instance");
			Assert.notNull(this.instance.username, "username must not be null");
			Assert.notNull(this.instance.getDn(), "Distinguished name must not be null");

			this.instance.authorities = Collections.unmodifiableList(this.mutableAuthorities);

			LdapUserDetails newInstance = this.instance;

			this.instance = null;

			return newInstance;
		}

		public Collection<GrantedAuthority> getGrantedAuthorities() {
			return this.mutableAuthorities;
		}

		public void setAccountNonExpired(boolean accountNonExpired) {
			this.instance.accountNonExpired = accountNonExpired;
		}

		public void setAccountNonLocked(boolean accountNonLocked) {
			this.instance.accountNonLocked = accountNonLocked;
		}

		public void setAuthorities(Collection<? extends GrantedAuthority> authorities) {
			this.mutableAuthorities = new ArrayList<>();
			this.mutableAuthorities.addAll(authorities);
		}

		public void setCredentialsNonExpired(boolean credentialsNonExpired) {
			this.instance.credentialsNonExpired = credentialsNonExpired;
		}

		public void setDn(String dn) {
			this.instance.dn = dn;
		}

		public void setDn(Name dn) {
			this.instance.dn = dn.toString();
		}

		public void setEnabled(boolean enabled) {
			this.instance.enabled = enabled;
		}

		public void setPassword(String password) {
			this.instance.password = password;
		}

		public void setUsername(String username) {
			this.instance.username = username;
		}

		public void setTimeBeforeExpiration(int timeBeforeExpiration) {
			this.instance.timeBeforeExpiration = timeBeforeExpiration;
		}

		public void setGraceLoginsRemaining(int graceLoginsRemaining) {
			this.instance.graceLoginsRemaining = graceLoginsRemaining;
		}

	}

}
