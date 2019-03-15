/*
 * Copyright 2002-2018 the original author or authors.
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

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

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
import java.util.stream.Collectors;

/**
 * The default implementation of an {@link OAuth2User}.
 *
 * <p>
 * User attribute names are <b>not</b> standardized between providers
 * and therefore it is required to supply the <i>key</i>
 * for the user's &quot;name&quot; attribute to one of the constructors.
 * The <i>key</i> will be used for accessing the &quot;name&quot; of the
 * {@code Principal} (user) via {@link #getAttributes()}
 * and returning it from {@link #getName()}.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2User
 */
public class DefaultOAuth2User implements OAuth2User, Serializable {
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	private final Set<GrantedAuthority> authorities;
	private final Map<String, Object> attributes;
	private final String nameAttributeKey;

	/**
	 * Constructs a {@code DefaultOAuth2User} using the provided parameters.
	 *
	 * @param authorities the authorities granted to the user
	 * @param attributes the attributes about the user
	 * @param nameAttributeKey the key used to access the user's &quot;name&quot; from {@link #getAttributes()}
	 */
	public DefaultOAuth2User(Collection<? extends GrantedAuthority> authorities, Map<String, Object> attributes, String nameAttributeKey) {
		Assert.notEmpty(authorities, "authorities cannot be empty");
		Assert.notEmpty(attributes, "attributes cannot be empty");
		Assert.hasText(nameAttributeKey, "nameAttributeKey cannot be empty");
		if (!attributes.containsKey(nameAttributeKey)) {
			throw new IllegalArgumentException("Missing attribute '" + nameAttributeKey + "' in attributes");
		}
		this.authorities = Collections.unmodifiableSet(new LinkedHashSet<>(this.sortAuthorities(authorities)));
		this.attributes = Collections.unmodifiableMap(new LinkedHashMap<>(attributes));
		this.nameAttributeKey = nameAttributeKey;
	}

	@Override
	public String getName() {
		return this.getAttributes().get(this.nameAttributeKey).toString();
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
		SortedSet<GrantedAuthority> sortedAuthorities =
			new TreeSet<>(Comparator.comparing(GrantedAuthority::getAuthority));
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
		sb.append(this.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(", ")));
		sb.append("], User Attributes: [");
		sb.append(this.getAttributes().entrySet().stream().map(e -> e.getKey() + "=" + e.getValue()).collect(Collectors.joining(", ")));
		sb.append("]");
		return sb.toString();
	}
}
