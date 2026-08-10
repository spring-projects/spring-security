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

import java.util.Collection;
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
 * evaluating if the {@link Authentication} contains any of the specified authorities.
 *
 * @author Evgeniy Cheban
 * @since 6.1
 */
public final class AuthoritiesAuthorizationManager implements AuthorizationManager<Collection<String>> {

	private RoleHierarchy roleHierarchy = new NullRoleHierarchy();

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
	 * @param authorities the collection of authority strings to check
	 * @return an {@link AuthorityAuthorizationDecision}
	 */
	@Override
	public AuthorizationResult authorize(Supplier<? extends @Nullable Authentication> authentication,
			Collection<String> authorities) {
		boolean granted = isGranted(authentication.get(), authorities);
		return new AuthorityAuthorizationDecision(granted, AuthorityUtils.createAuthorityList(authorities));
	}

	private boolean isGranted(Authentication authentication, Collection<String> authorities) {
		return authentication != null && isAuthorized(authentication, authorities);
	}

	private boolean isAuthorized(Authentication authentication, Collection<String> authorities) {
		for (GrantedAuthority grantedAuthority : getGrantedAuthorities(authentication)) {
			String authority = grantedAuthority.getAuthority();
			if (authority == null) {
				continue;
			}
			if (authorities.contains(authority)) {
				return true;
			}
		}
		return false;
	}

	private Collection<? extends GrantedAuthority> getGrantedAuthorities(Authentication authentication) {
		return this.roleHierarchy.getReachableGrantedAuthorities(authentication.getAuthorities());
	}

}
