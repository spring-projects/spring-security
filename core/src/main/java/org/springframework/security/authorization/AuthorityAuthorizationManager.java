/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.authorization;

import java.util.Set;
import java.util.function.Supplier;

import org.springframework.security.access.hierarchicalroles.NullRoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * An {@link AuthorizationManager} that determines if the current user is authorized by
 * evaluating if the {@link Authentication} contains a specified authority.
 *
 * @param <T> the type of object being authorized.
 * @author Evgeniy Cheban
 * @since 5.5
 */
public final class AuthorityAuthorizationManager<T> implements AuthorizationManager<T> {

	private static final String ROLE_PREFIX = "ROLE_";

	private final AuthoritiesAuthorizationManager delegate = new AuthoritiesAuthorizationManager();

	private final Set<String> authorities;

	private AuthorityAuthorizationManager(String... authorities) {
		this.authorities = Set.of(authorities);
	}

	/**
	 * Sets the {@link RoleHierarchy} to be used. Default is {@link NullRoleHierarchy}.
	 * Cannot be null.
	 * @param roleHierarchy the {@link RoleHierarchy} to use
	 * @since 5.8
	 */
	public void setRoleHierarchy(RoleHierarchy roleHierarchy) {
		this.delegate.setRoleHierarchy(roleHierarchy);
	}

	/**
	 * Creates an instance of {@link AuthorityAuthorizationManager} with the provided
	 * authority.
	 * @param role the authority to check for prefixed with "ROLE_". Role should not start
	 * with "ROLE_" since it is automatically prepended already.
	 * @param <T> the type of object being authorized
	 * @return the new instance
	 */
	public static <T> AuthorityAuthorizationManager<T> hasRole(String role) {
		Assert.notNull(role, "role cannot be null");
		Assert.isTrue(!role.startsWith(ROLE_PREFIX), () -> role + " should not start with " + ROLE_PREFIX + " since "
				+ ROLE_PREFIX + " is automatically prepended when using hasRole. Consider using hasAuthority instead.");
		return hasAuthority(ROLE_PREFIX + role);
	}

	/**
	 * Creates an instance of {@link AuthorityAuthorizationManager} with the provided
	 * authority.
	 * @param authority the authority to check for
	 * @param <T> the type of object being authorized
	 * @return the new instance
	 */
	public static <T> AuthorityAuthorizationManager<T> hasAuthority(String authority) {
		Assert.notNull(authority, "authority cannot be null");
		return new AuthorityAuthorizationManager<>(authority);
	}

	/**
	 * Creates an instance of {@link AuthorityAuthorizationManager} with the provided
	 * authorities.
	 * @param roles the authorities to check for prefixed with "ROLE_". Each role should
	 * not start with "ROLE_" since it is automatically prepended already.
	 * @param <T> the type of object being authorized
	 * @return the new instance
	 */
	public static <T> AuthorityAuthorizationManager<T> hasAnyRole(String... roles) {
		return hasAnyRole(ROLE_PREFIX, roles);
	}

	/**
	 * Creates an instance of {@link AuthorityAuthorizationManager} with the provided
	 * authorities.
	 * @param rolePrefix the role prefix for <code>roles</code>
	 * @param roles the authorities to check for prefixed with <code>rolePrefix</code>
	 * @param <T> the type of object being authorized
	 * @return the new instance
	 */
	public static <T> AuthorityAuthorizationManager<T> hasAnyRole(String rolePrefix, String[] roles) {
		Assert.notNull(rolePrefix, "rolePrefix cannot be null");
		Assert.notEmpty(roles, "roles cannot be empty");
		Assert.noNullElements(roles, "roles cannot contain null values");
		return hasAnyAuthority(toNamedRolesArray(rolePrefix, roles));
	}

	/**
	 * Creates an instance of {@link AuthorityAuthorizationManager} with the provided
	 * authorities.
	 * @param authorities the authorities to check for
	 * @param <T> the type of object being authorized
	 * @return the new instance
	 */
	public static <T> AuthorityAuthorizationManager<T> hasAnyAuthority(String... authorities) {
		Assert.notEmpty(authorities, "authorities cannot be empty");
		Assert.noNullElements(authorities, "authorities cannot contain null values");
		return new AuthorityAuthorizationManager<>(authorities);
	}

	private static String[] toNamedRolesArray(String rolePrefix, String[] roles) {
		String[] result = new String[roles.length];
		for (int i = 0; i < roles.length; i++) {
			String role = roles[i];
			Assert.isTrue(rolePrefix.isEmpty() || !role.startsWith(rolePrefix), () -> role + " should not start with "
					+ rolePrefix + " since " + rolePrefix
					+ " is automatically prepended when using hasAnyRole. Consider using hasAnyAuthority instead.");
			result[i] = rolePrefix + role;
		}
		return result;
	}

	/**
	 * Determines if the current user is authorized by evaluating if the
	 * {@link Authentication} contains a specified authority.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param object the {@link T} object to check
	 * @return an {@link AuthorizationDecision}
	 * @deprecated please use {@link #authorize(Supplier, Object)} instead
	 */
	@Deprecated
	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, T object) {
		return this.delegate.check(authentication, this.authorities);
	}

	@Override
	public String toString() {
		return "AuthorityAuthorizationManager[authorities=" + this.authorities + "]";
	}

}
