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

	public CurrRole role(String role_1) {
		return new CurrRole(role_1, this);
	}

	private void addReachableRole(String currRole, String nextReachableRole) {
		Set<GrantedAuthority> reachableRoles = rolesReachableInOneStepMap
				.getOrDefault(currRole, new HashSet<>());

		reachableRoles
				.add(new SimpleGrantedAuthority(nextReachableRole));

		rolesReachableInOneStepMap
				.put(currRole, reachableRoles);
	}

	private Map<String, Set<GrantedAuthority>> getRolesReachableInOneStepMap() {
		return this.rolesReachableInOneStepMap;
	}

	public static class CurrRole {

		private final String currRole;
		private final RoleHierarchyBuilder roleHierarchyBuilder;

		private CurrRole(String role_1, RoleHierarchyBuilder roleHierarchyBuilder) {
			this.currRole = role_1;
			this.roleHierarchyBuilder = roleHierarchyBuilder;
		}

		public CurrRole includes(String role_2) {
			roleHierarchyBuilder.addReachableRole(currRole, role_2);
			return new CurrRole(role_2, roleHierarchyBuilder);
		}

		public RoleHierarchyBuilder and() {
			return roleHierarchyBuilder;
		}

		public RoleHierarchy build() {
			return new RoleHierarchyImpl(this.roleHierarchyBuilder.getRolesReachableInOneStepMap());
		}
	}
}
