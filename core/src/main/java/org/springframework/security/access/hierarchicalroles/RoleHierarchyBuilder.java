/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.access.hierarchicalroles;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * The simple interface of a role hierarchy.
 *
 * @author Sebastijan Grabar
 */
public class RoleHierarchyBuilder {
	private final Map<String, Set<GrantedAuthority>> rolesReachableInOneStepMap = new HashMap<>();

	private RoleHierarchyBuilder() {
	}

	public static RoleHierarchyBuilder builder() {
		return new RoleHierarchyBuilder();
	}

	public FirstRoleBuilder role(String role_1) {
		return new FirstRoleBuilder(role_1, this);
	}

	private void addReachableRole(String currRole, String nextReachableRole) {
		Set<GrantedAuthority> reachableRoles = rolesReachableInOneStepMap
				.getOrDefault(currRole, new HashSet<>());

		reachableRoles
				.add(new SimpleGrantedAuthority(nextReachableRole));

		rolesReachableInOneStepMap
				.put(currRole, reachableRoles);
	}

	private static abstract class BaseRoleBuilder {
		private final RoleHierarchyBuilder roleHierarchyBuilder;

		BaseRoleBuilder(RoleHierarchyBuilder roleHierarchyBuilder) {
			this.roleHierarchyBuilder = roleHierarchyBuilder;
		}

		public RoleHierarchy build() {
			return new RoleHierarchyImpl(this.roleHierarchyBuilder.rolesReachableInOneStepMap);
		}
	}

	public static class FirstRoleBuilder extends BaseRoleBuilder {

		private final String currRole;
		private final RoleHierarchyBuilder roleHierarchyBuilder;

		private FirstRoleBuilder(String role_1, RoleHierarchyBuilder roleHierarchyBuilder) {
			super(roleHierarchyBuilder);
			this.currRole = role_1;
			this.roleHierarchyBuilder = roleHierarchyBuilder;
		}

		public NextRoleBuilder includes(String role_2) {
			roleHierarchyBuilder.addReachableRole(currRole, role_2);
			return new NextRoleBuilder(role_2, roleHierarchyBuilder);
		}
	}

	public static class NextRoleBuilder extends BaseRoleBuilder {

		private final String currRole;
		private final RoleHierarchyBuilder roleHierarchyBuilder;

		private NextRoleBuilder(String role_1, RoleHierarchyBuilder roleHierarchyBuilder) {
			super(roleHierarchyBuilder);
			this.currRole = role_1;
			this.roleHierarchyBuilder = roleHierarchyBuilder;
		}

		public NextRoleBuilder whichIncludes(String role_2) {
			roleHierarchyBuilder.addReachableRole(currRole, role_2);
			return new NextRoleBuilder(role_2, roleHierarchyBuilder);
		}

		public RoleHierarchyBuilder and() {
			return roleHierarchyBuilder;
		}
	}
}
