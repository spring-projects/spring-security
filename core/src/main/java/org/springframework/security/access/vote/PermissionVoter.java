/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.access.vote;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * Votes if a given given user permission string implies a defined permission string. This voter can be used instead of
 * a {@link org.springframework.security.access.vote.RoleVoter} when working with permissions. The voter turns and keeps
 * given permissions strings into {@link Permission} for easier processing.
 *
 * @author Marco Schaub
 */
public class PermissionVoter implements AccessDecisionVoter<Object> {

	private static final HashMap<String, Permission> PERMISSION_MAP = new HashMap();

	@Override
	public boolean supports(ConfigAttribute attribute) {
		return attribute.getAttribute() != null && attribute instanceof SecurityConfig;
	}

	@Override
	public boolean supports(Class clazz) {
		return true;
	}

	@Override
	public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
		if (authentication != null) {
			for (ConfigAttribute requiredPermissionString : attributes) {
				Permission requiredPermission = getPermissionForString(requiredPermissionString.getAttribute());
				for (GrantedAuthority grantedAuthority : authentication.getAuthorities()) {
					Permission grantedPermission = getPermissionForString(grantedAuthority.getAuthority());
					if (grantedPermission.implies(requiredPermission)) {
						return ACCESS_GRANTED;
					}
				}
			}
		}
		return ACCESS_DENIED;
	}

	/**
	 * A static method to verify a permission based access programmatically. If multiple permissions Strings are
	 * supplied, an OR evaluation will be made.
	 *
	 * @param authentication A {@link Authentication} object.
	 * @param requiredPermissions One or multiple permissions to check for.
	 * @return true if the {@code Authentication} contains a {@code GrantedAuthority} which implies one of the given
	 * permission strings.
	 */
	public static boolean vote(Authentication authentication, String... requiredPermissions) {
		List<ConfigAttribute> attributes = Arrays.stream(requiredPermissions).map(permissionString -> new SecurityConfig(permissionString)).collect(Collectors.toList());
		int decision = new PermissionVoter().vote(authentication, null, attributes);
		return decision > 0;
	}

	private static Permission getPermissionForString(String permissionString) {
		Permission permission = PERMISSION_MAP.get(permissionString);
		if (permission == null) {
			permission = new Permission(permissionString);
			PERMISSION_MAP.put(permissionString, permission);
		}
		return permission;
	}
}
