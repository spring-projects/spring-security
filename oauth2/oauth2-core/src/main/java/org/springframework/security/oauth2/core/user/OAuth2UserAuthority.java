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

import java.net.URL;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import org.springframework.lang.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

/**
 * A {@link GrantedAuthority} that may be associated to an {@link OAuth2User}.
 *
 * @author Joe Grandja
 * @author Yoobin Yoon
 * @since 5.0
 * @see OAuth2User
 */
public class OAuth2UserAuthority implements GrantedAuthority {

	private static final long serialVersionUID = 620L;

	private final String authority;

	private final Map<String, Object> attributes;

	@Deprecated
	private final String userNameAttributeName;

	private final String username;

	/**
	 * Constructs a {@code OAuth2UserAuthority} using the provided parameters and defaults
	 * {@link #getAuthority()} to {@code OAUTH2_USER}.
	 * @param attributes the attributes about the user
	 * @deprecated Use {@link #withUsername(String)} builder pattern instead
	 */
	@Deprecated
	public OAuth2UserAuthority(Map<String, Object> attributes) {
		this("OAUTH2_USER", attributes);
	}

	/**
	 * Constructs a {@code OAuth2UserAuthority} using the provided parameters and defaults
	 * {@link #getAuthority()} to {@code OAUTH2_USER}.
	 * @param attributes the attributes about the user
	 * @param userNameAttributeName the attribute name used to access the user's name from
	 * the attributes
	 * @since 6.4
	 * @deprecated Use {@link #withUsername(String)} builder pattern instead
	 */
	@Deprecated
	public OAuth2UserAuthority(Map<String, Object> attributes, @Nullable String userNameAttributeName) {
		this("OAUTH2_USER", attributes, userNameAttributeName);
	}

	/**
	 * Constructs a {@code OAuth2UserAuthority} using the provided parameters.
	 * @param authority the authority granted to the user
	 * @param attributes the attributes about the user
	 * @deprecated Use {@link #withUsername(String)} builder pattern instead
	 */
	@Deprecated
	public OAuth2UserAuthority(String authority, Map<String, Object> attributes) {
		this(authority, attributes, null);
	}

	/**
	 * Constructs a {@code OAuth2UserAuthority} using the provided parameters.
	 * @param authority the authority granted to the user
	 * @param attributes the attributes about the user
	 * @param userNameAttributeName the attribute name used to access the user's name from
	 * the attributes
	 * @since 6.4
	 * @deprecated Use {@link #withUsername(String)} builder pattern instead
	 */
	@Deprecated
	public OAuth2UserAuthority(String authority, Map<String, Object> attributes, String userNameAttributeName) {
		Assert.hasText(authority, "authority cannot be empty");
		Assert.notEmpty(attributes, "attributes cannot be empty");
		this.authority = authority;
		this.attributes = Collections.unmodifiableMap(new LinkedHashMap<>(attributes));
		this.userNameAttributeName = userNameAttributeName;
		this.username = (userNameAttributeName != null && attributes.get(userNameAttributeName) != null)
				? attributes.get(userNameAttributeName).toString() : null;
	}

	/**
	 * Constructs a {@code OAuth2UserAuthority} using the provided parameters.
	 * @param username the username
	 * @param authority the authority granted to the user
	 * @param attributes the attributes about the user
	 */
	protected OAuth2UserAuthority(String username, String authority, Map<String, Object> attributes) {
		Assert.hasText(username, "username cannot be empty");
		Assert.hasText(authority, "authority cannot be empty");
		Assert.notEmpty(attributes, "attributes cannot be empty");
		this.username = username;
		this.authority = authority;
		this.attributes = Collections.unmodifiableMap(new LinkedHashMap<>(attributes));
		this.userNameAttributeName = null;
	}

	/**
	 * Creates a new {@code OAuth2UserAuthority} builder with the username.
	 * @param username the username
	 * @return a new {@code Builder}
	 * @since 7.0
	 */
	public static Builder withUsername(String username) {
		return new Builder(username);
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

	/**
	 * Returns the attribute name used to access the user's name from the attributes.
	 * @return the attribute name used to access the user's name from the attributes
	 * @since 6.4
	 * @deprecated Use {@link #getUsername()} instead
	 */
	@Deprecated
	@Nullable
	public String getUserNameAttributeName() {
		return this.userNameAttributeName;
	}

	/**
	 * Returns the username of the OAuth2 user.
	 * <p>
	 * This method provides direct access to the username without requiring knowledge of
	 * the attribute structure or SpEL expressions used to extract it.
	 * @return the username
	 * @since 7.0
	 */
	public String getUsername() {
		return this.username;
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
		if (!Objects.equals(this.username, that.username)) {
			return false;
		}
		Map<String, Object> thatAttributes = that.getAttributes();
		if (getAttributes().size() != thatAttributes.size()) {
			return false;
		}
		for (Map.Entry<String, Object> e : getAttributes().entrySet()) {
			String key = e.getKey();
			Object value = convertURLIfNecessary(e.getValue());
			if (value == null) {
				if (!(thatAttributes.get(key) == null && thatAttributes.containsKey(key))) {
					return false;
				}
			}
			else {
				Object thatValue = convertURLIfNecessary(thatAttributes.get(key));
				if (!value.equals(thatValue)) {
					return false;
				}
			}
		}
		return true;
	}

	@Override
	public int hashCode() {
		int result = this.getAuthority().hashCode();
		result = 31 * result + Objects.hashCode(this.username);
		for (Map.Entry<String, Object> e : getAttributes().entrySet()) {
			Object key = e.getKey();
			Object value = convertURLIfNecessary(e.getValue());
			result += Objects.hashCode(key) ^ Objects.hashCode(value);
		}
		return result;
	}

	@Override
	public String toString() {
		return this.getAuthority();
	}

	/**
	 * @return {@code URL} converted to a string since {@code URL} shouldn't be used for
	 * equality/hashCode. For other instances the value is returned as is.
	 */
	private static Object convertURLIfNecessary(Object value) {
		return (value instanceof URL) ? ((URL) value).toExternalForm() : value;
	}

	/**
	 * A builder for {@link OAuth2UserAuthority}.
	 *
	 * @since 7.0
	 */
	public static class Builder {

		protected final String username;

		protected String authority = "OAUTH2_USER";

		protected Map<String, Object> attributes;

		protected Builder(String username) {
			Assert.hasText(username, "username cannot be empty");
			this.username = username;
		}

		public Builder authority(String authority) {
			this.authority = authority;
			return this;
		}

		public Builder attributes(Map<String, Object> attributes) {
			this.attributes = attributes;
			return this;
		}

		public OAuth2UserAuthority build() {
			Assert.notEmpty(this.attributes, "attributes cannot be empty");
			return new OAuth2UserAuthority(this.username, this.authority, this.attributes);
		}

	}

}
