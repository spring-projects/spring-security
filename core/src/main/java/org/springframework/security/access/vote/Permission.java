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

import java.util.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.AntPathMatcher;

/**
 * A {@link GrantedAuthority} which represents a hirachical security permission based on a permission string. A
 * permission consists at least of a path, can contain permission tokens and instance object identifiers. The three
 * token groups (path, permission object identifier) are seperated with a ":". The levels of the path are seperated with
 * a ".". Multiple permission token or object identifiers are seperated with a ",". * Example:
 * <ul>
 * <li>"test.userManagmenet.users:read,write:userId1,userId2" = Permits to read and write users of the userManagmenet of
 * test. </li>
 * <li>"**" = Permits to all actions on every resource. </li>
 * </ul>
 *
 * @author Marco Schaub
 */
class Permission implements GrantedAuthority {

	public static final String PERMISSION_SEPERATOR = ":";
	public static final String PATH_SEPERATOR = ".";
	public static final String WILDCARD = "*";
	private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher(".");

	private final String permissionString;
	private Set<String> instanceObjects = new HashSet(Arrays.asList(WILDCARD));
	private Set<String> permissionTokens = new HashSet(Arrays.asList(WILDCARD));
	private final String path;

	/**
	 * Creates a {@code Permission} using the given permissionString
	 *
	 * @param permissionString
	 */
	public Permission(String permissionString) {
		this.permissionString = permissionString;
		String[] permissionParts = permissionString.split(PERMISSION_SEPERATOR);
		switch (permissionParts.length) {
			case 3:
				instanceObjects = new HashSet(Arrays.asList(permissionParts[2].split(",")));
			case 2:
				permissionTokens = new HashSet(Arrays.asList(permissionParts[1].split(",")));
			case 1:
				path = permissionParts[0];
				break;
			default:
				throw new IllegalArgumentException();
		}
	}

	@Override
	public String getAuthority() {
		return permissionString;
	}

	/**
	 * Compares the current {@code Permission} to another given {@code Permission}.
	 *
	 * @param requiredPermission The other {@code Permission} which should be implied by the current {@code Permission}.
	 * @return true if the current {@code Permission} implies the given other {@code Permission}
	 */
	public boolean implies(Permission requiredPermission) {
		if (PATH_MATCHER.matchStart(path, requiredPermission.path)) {
			if (requiredPermission.permissionTokens.contains(WILDCARD) || permissionTokens.contains(WILDCARD) || permissionTokens.containsAll(requiredPermission.permissionTokens)) {
				if (requiredPermission.instanceObjects.contains(WILDCARD) || instanceObjects.contains(WILDCARD) || instanceObjects.containsAll(requiredPermission.instanceObjects)) {
					return true;
				}
			}
		}
		return false;
	}
}
