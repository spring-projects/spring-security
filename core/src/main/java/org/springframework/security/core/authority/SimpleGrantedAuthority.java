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

package org.springframework.security.core.authority;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

/**
 * Basic concrete implementation of a {@link GrantedAuthority}.
 *
 * <p>
 * Stores a {@code String} representation of an authority granted to the
 * {@link org.springframework.security.core.Authentication Authentication} object.
 *
 * @author Luke Taylor
 * @author Yanming Zhou
 */
public final class SimpleGrantedAuthority implements GrantedAuthority {

	private static final long serialVersionUID = 620L;

	private final String role;

	/**
	 * Constructs a {@code SimpleGrantedAuthority} using the provided authority.
	 * @param authority The provided authority, including any prefix; for example,
	 * {@code ROLE_ADMIN}
	 */
	public SimpleGrantedAuthority(String authority) {
		Assert.hasText(authority, "A granted authority textual representation is required");
		this.role = authority;
	}

	@Override
	public String getAuthority() {
		return this.role;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj instanceof SimpleGrantedAuthority sga) {
			return this.role.equals(sga.getAuthority());
		}
		return false;
	}

	@Override
	public int hashCode() {
		return this.role.hashCode();
	}

	@Override
	public String toString() {
		return this.role;
	}

}
