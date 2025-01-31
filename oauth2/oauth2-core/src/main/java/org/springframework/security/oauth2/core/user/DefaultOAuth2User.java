/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.oauth2.core.user;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.util.Assert;

/**
 * The default implementation of an {@link OAuth2User}.
 *
 * @author Joe Grandja
 * @author Eddú Meléndez
 * @author Park Hyojong
 * @since 5.0
 * @see OAuth2User
 */
public class DefaultOAuth2User implements OAuth2User, Serializable {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final Set<GrantedAuthority> authorities;

	private final Map<String, Object> attributes;

	private final String name;

	/**
	 * Constructs a {@code DefaultOAuth2User} using the provided parameters.
	 * @param authorities the authorities granted to the user
	 * @param attributes the attributes about the user
	 * @param nameAttributeKey the key used to access the user's &quot;name&quot; from
	 * {@link #getAttributes()}
	 */
	@Deprecated
	public DefaultOAuth2User(Collection<? extends GrantedAuthority> authorities, Map<String, Object> attributes,
			String nameAttributeKey) {
		this(getNameFromAttributes(attributes, nameAttributeKey), attributes, authorities);
	}

	/**
	 * Constructs a {@code DefaultOAuth2User} using the provided parameters.
	 * @param name the name of the user
	 * @param authorities the authorities granted to the user
	 * @param attributes the attributes about the user
	 */
	public DefaultOAuth2User(String name, Map<String, Object> attributes,
			Collection<? extends GrantedAuthority> authorities) {
		Assert.notEmpty(attributes, "attributes cannot be empty");
		this.attributes = Collections.unmodifiableMap(new LinkedHashMap<>(attributes));
		this.authorities = (authorities != null)
				? Collections.unmodifiableSet(new LinkedHashSet<>(this.sortAuthorities(authorities)))
				: Collections.unmodifiableSet(new LinkedHashSet<>(AuthorityUtils.NO_AUTHORITIES));
		this.name = (name != null) ? name : (String) this.attributes.get("sub");
	}

	@Override
	public String getName() {
		return this.name;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	@Override
	public Map<String, Object> getAttributes() {
		return this.attributes;
	}

	private Set<GrantedAuthority> sortAuthorities(Collection<? extends GrantedAuthority> authorities) {
		SortedSet<GrantedAuthority> sortedAuthorities = new TreeSet<>(
				Comparator.comparing(GrantedAuthority::getAuthority));
		sortedAuthorities.addAll(authorities);
		return sortedAuthorities;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || this.getClass() != obj.getClass()) {
			return false;
		}
		DefaultOAuth2User that = (DefaultOAuth2User) obj;
		if (!this.getName().equals(that.getName())) {
			return false;
		}
		if (!this.getAuthorities().equals(that.getAuthorities())) {
			return false;
		}
		return this.getAttributes().equals(that.getAttributes());
	}

	@Override
	public int hashCode() {
		int result = this.getName().hashCode();
		result = 31 * result + this.getAuthorities().hashCode();
		result = 31 * result + this.getAttributes().hashCode();
		return result;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("Name: [");
		sb.append(this.getName());
		sb.append("], Granted Authorities: [");
		sb.append(getAuthorities());
		sb.append("], User Attributes: [");
		sb.append(getAttributes());
		sb.append("]");
		return sb.toString();
	}

	protected static String getNameFromAttributes(Map<String, Object> attributes, String nameAttributeKey) {
		Assert.hasText(nameAttributeKey, "nameAttributeKey cannot be empty");
		Assert.notNull(attributes.get(nameAttributeKey),
				"Attribute value for '" + nameAttributeKey + "' cannot be null");
		return attributes.get(nameAttributeKey).toString();
	}

	/**
	 * A builder for {@link DefaultOAuth2User}.
	 */
	public static class Builder {

		private String name;

		private String nameAttributeKey;

		private Map<String, Object> attributes;

		private Collection<? extends GrantedAuthority> authorities;

		/**
		 * Sets the name of the user.
		 * @param name the name of the user
		 * @return the {@link Builder}
		 */
		public Builder name(String name) {
			this.name = name;
			return this;
		}

		/**
		 * Sets the key used to access the user's &quot;name&quot; from the user attributes if no &quot;name&quot; is
		 * provided.
		 * @param nameAttributeKey the key used to access the user's &quot;name&quot; from the user attributes.
		 * @return the {@link Builder}
		 */
		public Builder nameAttributeKey(String nameAttributeKey) {
			this.nameAttributeKey = nameAttributeKey;
			return this;
		}

		/**
		 * Sets the attributes about the user.
		 * @param attributes the attributes about the user
		 * @return the {@link Builder}
		 */
		public Builder attributes(Map<String, Object> attributes) {
			this.attributes = attributes;
			return this;
		}

		/**
		 * Sets the authorities granted to the user.
		 * @param authorities the authorities granted to the user
		 * @return the {@link Builder}
		 */
		public Builder authorities(Collection<? extends GrantedAuthority> authorities) {
			this.authorities = authorities;
			return this;
		}

		/**
		 * Builds a new {@link DefaultOAuth2User}.
		 * @return a {@link DefaultOAuth2User}
		 */
		public DefaultOAuth2User build() {
			String name = this.name != null ? this.name : getNameFromAttributes(this.attributes, this.nameAttributeKey);
			return new DefaultOAuth2User(name, this.attributes, this.authorities);
		}

	}

}
