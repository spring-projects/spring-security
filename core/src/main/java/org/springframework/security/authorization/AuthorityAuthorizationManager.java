/*
 * Copyright 2002-2020 the original author or authors.
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

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Supplier;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

/**
 * An {@link AuthorizationManager} that determines if the current user is authorized by
 * evaluating if the {@link Authentication} contains a specified authority.
 *
 * @param <T> the type of object being authorized.
 * @author Evgeniy Cheban
 */
public final class AuthorityAuthorizationManager<T> implements AuthorizationManager<T> {

	private static final String ROLE_PREFIX = "ROLE_";

	private final Set<String> authorities;

	private AuthorityAuthorizationManager(String... authorities) {
		this.authorities = new HashSet<>(Arrays.asList(authorities));
	}

	/**
	 * Creates an instance of {@link AuthorityAuthorizationManager} with the provided
	 * authority.
	 * @param role the authority to check for prefixed with "ROLE_"
	 * @param <T> the type of object being authorized
	 * @return the new instance
	 */
	public static <T> AuthorityAuthorizationManager<T> hasRole(String role) {
		Assert.notNull(role, "role cannot be null");
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
	 * @param roles the authorities to check for prefixed with "ROLE_"
	 * @param <T> the type of object being authorized
	 * @return the new instance
	 */
	public static <T> AuthorityAuthorizationManager<T> hasAnyRole(String... roles) {
		Assert.notEmpty(roles, "roles cannot be empty");
		Assert.noNullElements(roles, "roles cannot contain null values");
		return hasAnyAuthority(toNamedRolesArray(roles));
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

	private static String[] toNamedRolesArray(String... roles) {
		String[] result = new String[roles.length];
		for (int i = 0; i < roles.length; i++) {
			result[i] = ROLE_PREFIX + roles[i];
		}
		return result;
	}

	/**
	 * Determines if the current user is authorized by evaluating if the
	 * {@link Authentication} contains a specified authority.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param object the {@link T} object to check
	 * @return an {@link AuthorizationDecision}
	 */
	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, T object) {
		boolean granted = isGranted(authentication.get());
		return new AuthorizationDecision(granted);
	}

	private boolean isGranted(Authentication authentication) {
		return authentication != null && authentication.isAuthenticated() && isAuthorized(authentication);
	}

	private boolean isAuthorized(Authentication authentication) {
		for (GrantedAuthority grantedAuthority : authentication.getAuthorities()) {
			String authority = grantedAuthority.getAuthority();
			if (this.authorities.contains(authority)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public String toString() {
		return "AuthorityAuthorizationManager[authorities=" + this.authorities + "]";
	}

}
