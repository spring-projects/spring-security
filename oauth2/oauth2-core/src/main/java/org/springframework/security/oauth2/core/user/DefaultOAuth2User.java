/*
 * Copyright 2004-present the original author or authors.
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
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.util.Assert;

/**
 * The default implementation of an {@link OAuth2User}.
 *
 * <p>
 * User attribute names are <b>not</b> standardized between providers and therefore it is
 * required to supply the <i>key</i> for the user's &quot;name&quot; attribute to one of
 * the constructors. The <i>key</i> will be used for accessing the &quot;name&quot; of the
 * {@code Principal} (user) via {@link #getAttributes()} and returning it from
 * {@link #getName()}.
 *
 * @author Joe Grandja
 * @author Eddú Meléndez
 * @author Park Hyojong
 * @author YooBin Yoon
 * @since 5.0
 * @see OAuth2User
 */
public class DefaultOAuth2User implements OAuth2User, Serializable {

	private static final long serialVersionUID = 620L;

	private final Set<GrantedAuthority> authorities;

	private final Map<String, Object> attributes;

	private final String nameAttributeKey;

	private final String username;

	/**
	 * Constructs a {@code DefaultOAuth2User} using the provided parameters.
	 * @param authorities the authorities granted to the user
	 * @param attributes the attributes about the user
	 * @param nameAttributeKey the key used to access the user's &quot;name&quot; from
	 * {@link #getAttributes()}
	 * @deprecated Use {@link #withUsername(String)} builder pattern instead
	 */
	@Deprecated
	public DefaultOAuth2User(Collection<? extends GrantedAuthority> authorities, Map<String, Object> attributes,
			String nameAttributeKey) {
		Assert.notEmpty(attributes, "attributes cannot be empty");
		Assert.hasText(nameAttributeKey, "nameAttributeKey cannot be empty");
		Assert.notNull(attributes.get(nameAttributeKey),
				"Attribute value for '" + nameAttributeKey + "' cannot be null");

		this.authorities = (authorities != null)
				? Collections.unmodifiableSet(new LinkedHashSet<>(this.sortAuthorities(authorities)))
				: Collections.unmodifiableSet(new LinkedHashSet<>(AuthorityUtils.NO_AUTHORITIES));
		this.attributes = Collections.unmodifiableMap(new LinkedHashMap<>(attributes));
		this.nameAttributeKey = nameAttributeKey;
		this.username = attributes.get(nameAttributeKey).toString();
	}

	/**
	 * Constructs a {@code DefaultOAuth2User} using the provided parameters. This
	 * constructor is used by Jackson for deserialization.
	 * @param authorities the authorities granted to the user
	 * @param attributes the attributes about the user
	 * @param nameAttributeKey the key used to access the user's &quot;name&quot; from
	 * {@link #getAttributes()} - preserved for backwards compatibility
	 * @param username the user's name
	 */
	private DefaultOAuth2User(Collection<? extends GrantedAuthority> authorities, Map<String, Object> attributes,
			String nameAttributeKey, String username) {
		Assert.notEmpty(attributes, "attributes cannot be empty");

		this.authorities = (authorities != null)
				? Collections.unmodifiableSet(new LinkedHashSet<>(this.sortAuthorities(authorities)))
				: Collections.unmodifiableSet(new LinkedHashSet<>(AuthorityUtils.NO_AUTHORITIES));
		this.attributes = Collections.unmodifiableMap(new LinkedHashMap<>(attributes));
		this.nameAttributeKey = nameAttributeKey;
		this.username = (username != null) ? username : attributes.get(nameAttributeKey).toString();

		Assert.hasText(this.username, "username cannot be empty");
	}

	/**
	 * Creates a new {@code DefaultOAuth2User} builder with the username.
	 * @param username the user's name
	 * @return a new {@code Builder}
	 * @since 6.5
	 */
	public static Builder withUsername(String username) {
		return new Builder(username);
	}

	/**
	 * A builder for {@link DefaultOAuth2User}.
	 *
	 * @since 6.5
	 */
	public static final class Builder {

		private final String username;

		private Collection<? extends GrantedAuthority> authorities;

		private Map<String, Object> attributes;

		private Builder(String username) {
			Assert.hasText(username, "username cannot be empty");
			this.username = username;
		}

		public Builder authorities(Collection<? extends GrantedAuthority> authorities) {
			this.authorities = authorities;
			return this;
		}

		public Builder attributes(Map<String, Object> attributes) {
			this.attributes = attributes;
			return this;
		}

		public DefaultOAuth2User build() {
			Assert.notEmpty(this.attributes, "attributes cannot be empty");
			return new DefaultOAuth2User(this.authorities, this.attributes, null, this.username);
		}

	}

	@Override
	public String getName() {
		return this.username;
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

}
