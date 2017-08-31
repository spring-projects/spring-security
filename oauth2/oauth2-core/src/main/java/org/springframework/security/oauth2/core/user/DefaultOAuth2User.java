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
package org.springframework.security.oauth2.core.user;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

import java.util.*;
import java.util.stream.Collectors;

/**
 * The default implementation of an {@link OAuth2User}.
 *
 * <p>
 * User attribute names are <b><i>not</i></b> standardized between providers
 * and therefore it is required that the user supply the <i>key</i>
 * for the user's &quot;name&quot; attribute to one of the constructors.
 * The <i>key</i> will be used for accessing the &quot;name&quot; of the
 * <code>Principal</code> (user) via {@link #getAttributes()}
 * and returning it from {@link #getName()}.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2User
 */
public class DefaultOAuth2User implements OAuth2User {
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	private final Set<GrantedAuthority> authorities;
	private Map<String, Object> attributes;
	private final String nameAttributeKey;

	public DefaultOAuth2User(Set<GrantedAuthority> authorities, Map<String, Object> attributes, String nameAttributeKey) {
		Assert.notEmpty(authorities, "authorities cannot be empty");
		Assert.notEmpty(attributes, "attributes cannot be empty");
		Assert.hasText(nameAttributeKey, "nameAttributeKey cannot be empty");
		if (!attributes.containsKey(nameAttributeKey)) {
			throw new IllegalArgumentException("Invalid nameAttributeKey: " + nameAttributeKey);
		}
		this.authorities = Collections.unmodifiableSet(this.sortAuthorities(authorities));
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

	private Set<GrantedAuthority> sortAuthorities(Set<GrantedAuthority> authorities) {
		SortedSet<GrantedAuthority> sortedAuthorities =
			new TreeSet<>((g1, g2) -> g1.getAuthority().compareTo(g2.getAuthority()));
		authorities.stream().forEach(sortedAuthorities::add);
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
