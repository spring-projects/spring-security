/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.core.userdetails;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.io.Serializable;
import java.util.*;

/**
 * @author Joe Grandja
 */
public class OAuth2User implements OAuth2UserDetails {
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	public static final String USERNAME_ATTRIBUTE_NAME_EMAIL = "email";
	public static final String USERNAME_ATTRIBUTE_NAME_ID = "id";
	private final OAuth2UserAttribute identifier;
	private final List<OAuth2UserAttribute> attributes;
	private String userNameAttributeName;
	private final Set<GrantedAuthority> authorities;
	private final boolean accountNonExpired;
	private final boolean accountNonLocked;
	private final boolean credentialsNonExpired;
	private final boolean enabled;


	public OAuth2User(OAuth2UserAttribute identifier, List<OAuth2UserAttribute> attributes) {
		this(identifier, attributes, Collections.emptySet());
	}

	public OAuth2User(OAuth2UserAttribute identifier, List<OAuth2UserAttribute> attributes, Set<GrantedAuthority> authorities) {
		this(identifier, attributes, authorities, true, true, true, true);
	}

	public OAuth2User(OAuth2UserAttribute identifier, List<OAuth2UserAttribute> attributes, Set<GrantedAuthority> authorities,
						boolean accountNonExpired, boolean accountNonLocked, boolean credentialsNonExpired, boolean enabled) {

		Assert.notNull(identifier, "identifier cannot be null");
		this.identifier = identifier;

		Assert.notEmpty(attributes, "attributes cannot be empty");
		this.attributes = Collections.unmodifiableList(attributes);

		this.userNameAttributeName = USERNAME_ATTRIBUTE_NAME_EMAIL;
		this.authorities = Collections.unmodifiableSet(this.sortAuthorities(authorities));
		this.accountNonExpired = accountNonExpired;
		this.accountNonLocked = accountNonLocked;
		this.credentialsNonExpired = credentialsNonExpired;
		this.enabled = enabled;
	}

	@Override
	public OAuth2UserAttribute getIdentifier() {
		return this.identifier;
	}

	@Override
	public List<OAuth2UserAttribute> getAttributes() {
		return this.attributes;
	}

	public String getUserNameAttributeName() {
		return this.userNameAttributeName;
	}

	public void setUserNameAttributeName(String userNameAttributeName) {
		Assert.notNull(userNameAttributeName, "userNameAttributeName cannot be null");
		this.userNameAttributeName = userNameAttributeName;
	}

	public OAuth2UserAttribute getAttribute(String name) {
		Optional<OAuth2UserAttribute> userAttribute = this.getAttributes().stream()
				.filter(e -> e.getName().equalsIgnoreCase(name)).findFirst();
		return (userAttribute.isPresent() ? userAttribute.get() : null);
	}

	public String getAttributeString(String name) {
		OAuth2UserAttribute userAttribute = this.getAttribute(name);
		return (userAttribute != null ? userAttribute.getValue().toString() : null);
	}

	public Long getAttributeLong(String name) {
		try {
			return Long.valueOf(this.getAttributeString(name));
		} catch (NumberFormatException ex) {
			return -1L;
		}
	}

	public Boolean getAttributeBoolean(String name) {
		return Boolean.valueOf(this.getAttributeString(name));
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	@Override
	public String getPassword() {
		// Password is never known (or exposed).
		// This user is registered with the OAuth2 Provider
		// which never exposes the password.
		return null;
	}

	@Override
	public String getUsername() {
		String userName = this.getAttributeString(this.getUserNameAttributeName());
		if (userName == null && !USERNAME_ATTRIBUTE_NAME_ID.equals(this.getUserNameAttributeName())) {
			// Default to 'id' attribute
			userName = this.getAttributeString(USERNAME_ATTRIBUTE_NAME_ID);
		}
		return userName;
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

	private Set<GrantedAuthority> sortAuthorities(Set<GrantedAuthority> authorities) {
		if (CollectionUtils.isEmpty(authorities)) {
			return Collections.emptySet();
		}

		SortedSet<GrantedAuthority> sortedAuthorities =
				new TreeSet<>(new GrantedAuthorityComparator());
		authorities.stream().forEach(sortedAuthorities::add);

		return sortedAuthorities;
	}

	private static class GrantedAuthorityComparator implements Comparator<GrantedAuthority>, Serializable {
		private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

		public int compare(GrantedAuthority g1, GrantedAuthority g2) {
			return g1.getAuthority().compareTo(g2.getAuthority());
		}
	}
}
