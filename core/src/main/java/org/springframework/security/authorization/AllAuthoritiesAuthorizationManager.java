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

package org.springframework.security.authorization;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;

import org.jspecify.annotations.Nullable;

import org.springframework.security.access.hierarchicalroles.NullRoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.util.Assert;

/**
 * An {@link AuthorizationManager} that determines if the current user is authorized by
 * evaluating if the {@link Authentication} contains all the specified authorities.
 *
 * @author Rob Winch
 * @since 7.0
 * @see AuthorityAuthorizationManager
 */
public final class AllAuthoritiesAuthorizationManager<T> implements AuthorizationManager<T> {

	private static final String ROLE_PREFIX = "ROLE_";

	private RoleHierarchy roleHierarchy = new NullRoleHierarchy();

	private final List<String> requiredAuthorities;

	/**
	 * Creates a new instance.
	 * @param requiredAuthorities the authorities that are required.
	 */
	private AllAuthoritiesAuthorizationManager(String... requiredAuthorities) {
		Assert.notEmpty(requiredAuthorities, "requiredAuthorities cannot be empty");
		this.requiredAuthorities = Arrays.asList(requiredAuthorities);
	}

	/**
	 * Sets the {@link RoleHierarchy} to be used. Default is {@link NullRoleHierarchy}.
	 * Cannot be null.
	 * @param roleHierarchy the {@link RoleHierarchy} to use
	 */
	public void setRoleHierarchy(RoleHierarchy roleHierarchy) {
		Assert.notNull(roleHierarchy, "roleHierarchy cannot be null");
		this.roleHierarchy = roleHierarchy;
	}

	/**
	 * Determines if the current user is authorized by evaluating if the
	 * {@link Authentication} contains any of specified authorities.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param object the object to check authorization on (not used).
	 * @return an {@link AuthorityAuthorizationDecision}
	 */
	@Override
	public AuthorityAuthorizationDecision authorize(Supplier<? extends @Nullable Authentication> authentication,
			T object) {
		List<String> authenticatedAuthorities = getGrantedAuthorities(authentication.get());
		List<String> missingAuthorities = new ArrayList<>(this.requiredAuthorities);
		missingAuthorities.removeIf(authenticatedAuthorities::contains);
		return new AuthorityAuthorizationDecision(missingAuthorities.isEmpty(),
				AuthorityUtils.createAuthorityList(missingAuthorities));
	}

	private List<String> getGrantedAuthorities(Authentication authentication) {
		if (authentication == null || !authentication.isAuthenticated()) {
			return Collections.emptyList();
		}
		return this.roleHierarchy.getReachableGrantedAuthorities(authentication.getAuthorities())
			.stream()
			.map(GrantedAuthority::getAuthority)
			.toList();
	}

	/**
	 * Creates an instance of {@link AllAuthoritiesAuthorizationManager} with the provided
	 * authorities.
	 * @param roles the authorities to check for prefixed with "ROLE_". Each role should
	 * not start with "ROLE_" since it is automatically prepended already.
	 * @param <T> the type of object being authorized
	 * @return the new instance
	 */
	public static <T> AllAuthoritiesAuthorizationManager<T> hasAllRoles(String... roles) {
		return hasAllPrefixedAuthorities(ROLE_PREFIX, roles);
	}

	/**
	 * Creates an instance of {@link AllAuthoritiesAuthorizationManager} with the provided
	 * authorities.
	 * @param prefix the prefix for <code>authorities</code>
	 * @param authorities the authorities to check for prefixed with <code>prefix</code>
	 * @param <T> the type of object being authorized
	 * @return the new instance
	 */
	public static <T> AllAuthoritiesAuthorizationManager<T> hasAllPrefixedAuthorities(String prefix,
			String... authorities) {
		Assert.notNull(prefix, "rolePrefix cannot be null");
		Assert.notEmpty(authorities, "roles cannot be empty");
		Assert.noNullElements(authorities, "roles cannot contain null values");
		return hasAllAuthorities(toNamedRolesArray(prefix, authorities));
	}

	/**
	 * Creates an instance of {@link AllAuthoritiesAuthorizationManager} with the provided
	 * authorities.
	 * @param authorities the authorities to check for
	 * @param <T> the type of object being authorized
	 * @return the new instance
	 */
	public static <T> AllAuthoritiesAuthorizationManager<T> hasAllAuthorities(String... authorities) {
		Assert.notEmpty(authorities, "authorities cannot be empty");
		Assert.noNullElements(authorities, "authorities cannot contain null values");
		return new AllAuthoritiesAuthorizationManager<>(authorities);
	}

	/**
	 * Creates an instance of {@link AllAuthoritiesAuthorizationManager} with the provided
	 * authorities.
	 * @param authorities the authorities to check for
	 * @param <T> the type of object being authorized
	 * @return the new instance
	 */
	public static <T> AllAuthoritiesAuthorizationManager<T> hasAllAuthorities(List<String> authorities) {
		Assert.notEmpty(authorities, "authorities cannot be empty");
		Assert.noNullElements(authorities, "authorities cannot contain null values");
		return new AllAuthoritiesAuthorizationManager<>(authorities.toArray(new String[0]));
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

}
