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

import com.webauthn4j.util.ArrayUtil;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.webauthn.authenticator.WebAuthnAuthenticator;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.*;

/**
 * A {@link WebAuthnUserDetails} implementation
 *
 * @author Yoshikazu Nojima
 */
@SuppressWarnings("squid:S2160")
public class WebAuthnUser implements WebAuthnUserDetails {

	private final String username;
	private final Set<GrantedAuthority> authorities;
	private final boolean accountNonExpired;
	private final boolean accountNonLocked;
	private final boolean credentialsNonExpired;
	private final boolean enabled;
	// ~ Instance fields
	// ================================================================================================
	private byte[] userHandle;
	private List<WebAuthnAuthenticator> authenticators;

	public WebAuthnUser(
			byte[] userHandle, String username, List<WebAuthnAuthenticator> authenticators,
			Collection<? extends GrantedAuthority> authorities) {
		this(userHandle, username, authenticators,
				true, true, true, true,
				authorities);
	}

	@SuppressWarnings("squid:S00107")
	public WebAuthnUser(
			byte[] userHandle, String username, List<WebAuthnAuthenticator> authenticators, boolean enabled, boolean accountNonExpired,
			boolean credentialsNonExpired, boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities) {
		this.userHandle = ArrayUtil.clone(userHandle);
		this.username = username;
		this.authenticators = authenticators;
		this.enabled = enabled;
		this.accountNonExpired = accountNonExpired;
		this.credentialsNonExpired = credentialsNonExpired;
		this.accountNonLocked = accountNonLocked;
		this.authorities = Collections.unmodifiableSet(sortAuthorities(authorities));
	}

	private static SortedSet<GrantedAuthority> sortAuthorities(
			Collection<? extends GrantedAuthority> authorities) {
		Assert.notNull(authorities, "Cannot pass a null GrantedAuthority collection");
		// Ensure array iteration order is predictable (as per
		// UserDetails.getAuthorities() contract and SEC-717)
		SortedSet<GrantedAuthority> sortedAuthorities = new TreeSet<>(
				new AuthorityComparator());

		for (GrantedAuthority grantedAuthority : authorities) {
			Assert.notNull(grantedAuthority,
					"GrantedAuthority list cannot contain any null elements");
			sortedAuthorities.add(grantedAuthority);
		}

		return sortedAuthorities;
	}

	@Override
	public byte[] getUserHandle() {
		return ArrayUtil.clone(userHandle);
	}

	@Override
	public String getUsername() {
		return username;
	}

	@Override
	public List<WebAuthnAuthenticator> getAuthenticators() {
		return authenticators;
	}

	@Override
	public Set<GrantedAuthority> getAuthorities() {
		return authorities;
	}

	@Override
	public boolean isAccountNonExpired() {
		return accountNonExpired;
	}

	@Override
	public boolean isAccountNonLocked() {
		return accountNonLocked;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return credentialsNonExpired;
	}

	@Override
	public boolean isEnabled() {
		return enabled;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		WebAuthnUser that = (WebAuthnUser) o;
		return accountNonExpired == that.accountNonExpired &&
				accountNonLocked == that.accountNonLocked &&
				credentialsNonExpired == that.credentialsNonExpired &&
				enabled == that.enabled &&
				Arrays.equals(userHandle, that.userHandle) &&
				Objects.equals(username, that.username) &&
				Objects.equals(authenticators, that.authenticators) &&
				Objects.equals(authorities, that.authorities);
	}

	@Override
	public int hashCode() {
		int result = Objects.hash(username, authenticators, authorities, accountNonExpired, accountNonLocked, credentialsNonExpired, enabled);
		result = 31 * result + Arrays.hashCode(userHandle);
		return result;
	}

	private static class AuthorityComparator implements Comparator<GrantedAuthority>,
			Serializable {
		private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

		public int compare(GrantedAuthority g1, GrantedAuthority g2) {
			// Neither should ever be null as each entry is checked before adding it to
			// the set.
			// If the authority is null, it is a custom authority and should precede
			// others.
			if (g2.getAuthority() == null) {
				return -1;
			}

			if (g1.getAuthority() == null) {
				return 1;
			}

			return g1.getAuthority().compareTo(g2.getAuthority());
		}
	}
}
