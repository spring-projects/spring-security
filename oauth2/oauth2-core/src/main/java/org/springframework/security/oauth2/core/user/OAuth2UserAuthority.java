/*
 * Copyright 2002-2017 the original author or authors.
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

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

/**
 * A {@link GrantedAuthority} that may be associated to an {@link OAuth2User}.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2User
 */
public class OAuth2UserAuthority implements GrantedAuthority {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final String authority;

	private final Map<String, Object> attributes;

	/**
	 * Constructs a {@code OAuth2UserAuthority} using the provided parameters and defaults
	 * {@link #getAuthority()} to {@code ROLE_USER}.
	 * @param attributes the attributes about the user
	 */
	public OAuth2UserAuthority(Map<String, Object> attributes) {
		this("ROLE_USER", attributes);
	}

	/**
	 * Constructs a {@code OAuth2UserAuthority} using the provided parameters.
	 * @param authority the authority granted to the user
	 * @param attributes the attributes about the user
	 */
	public OAuth2UserAuthority(String authority, Map<String, Object> attributes) {
		Assert.hasText(authority, "authority cannot be empty");
		Assert.notEmpty(attributes, "attributes cannot be empty");
		this.authority = authority;
		this.attributes = Collections.unmodifiableMap(new LinkedHashMap<>(attributes));
	}

	@Override
	public String getAuthority() {
		return this.authority;
	}

	/**
	 * Returns the attributes about the user.
	 * @return a {@code Map} of attributes about the user
	 */
	public Map<String, Object> getAttributes() {
		return this.attributes;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || this.getClass() != obj.getClass()) {
			return false;
		}

		OAuth2UserAuthority that = (OAuth2UserAuthority) obj;

		if (!this.getAuthority().equals(that.getAuthority())) {
			return false;
		}
		return this.getAttributes().equals(that.getAttributes());
	}

	@Override
	public int hashCode() {
		int result = this.getAuthority().hashCode();
		result = 31 * result + this.getAttributes().hashCode();
		return result;
	}

	@Override
	public String toString() {
		return this.getAuthority();
	}

}
