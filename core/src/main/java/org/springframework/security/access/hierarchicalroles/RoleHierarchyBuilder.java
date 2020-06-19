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

import java.util.*;

/**
 * The simple interface of a role hierarchy.
 *
 * @author Sebastijan Grabar
 */
public class RoleHierarchyBuilder {
	private final Map<String, Set<GrantedAuthority>> rolesReachableInOneOrMoreStepsMap = new HashMap<>();

	private RoleHierarchyBuilder() {
	}

	public CurrRole role(String role_1) {
		return new CurrRole(role_1, this);
	}

	private void addReachableRole(String currRole, String nextReachableRole) {
		if (!rolesReachableInOneOrMoreStepsMap.containsKey(currRole)) {
			Set<GrantedAuthority> reachableRoles = new HashSet<>();
			reachableRoles
					.add(new SimpleGrantedAuthority(nextReachableRole));

			rolesReachableInOneOrMoreStepsMap
					.put(currRole, reachableRoles);
		} else {
			rolesReachableInOneOrMoreStepsMap
					.get(currRole)
					.add(new SimpleGrantedAuthority(nextReachableRole));
		}


		if (rolesReachableInOneOrMoreStepsMap.containsKey(nextReachableRole)) {
			rolesReachableInOneOrMoreStepsMap
					.get(currRole)
					.addAll(
							rolesReachableInOneOrMoreStepsMap
									.get(nextReachableRole)
					);
		}


	}

	private Map<String, Set<GrantedAuthority>> getRolesReachableInOneOrMoreStepsMap() {
		return Collections.unmodifiableMap(this.rolesReachableInOneOrMoreStepsMap);
	}


	public static class CurrRole {

		private final RoleHierarchyBuilder roleHierarchyBuilder;
		private final List<String> rolesTree = new ArrayList<>();

		private CurrRole(String role_1, RoleHierarchyBuilder roleHierarchyBuilder) {
			this.roleHierarchyBuilder = roleHierarchyBuilder;
			rolesTree.add(role_1);
		}

		public CurrRole includes(String role_2) {
			rolesTree.add(role_2);
			return this;
		}

		public RoleHierarchyBuilder and() {
			for (int i = rolesTree.size() - 2; i >= 0; i--) {
				roleHierarchyBuilder.addReachableRole(rolesTree.get(i), rolesTree.get(i + 1));
			}

			return roleHierarchyBuilder;
		}

		public RoleHierarchy build() {
			for (int i = rolesTree.size() - 2; i >= 0; i--) {
				roleHierarchyBuilder.addReachableRole(rolesTree.get(i), rolesTree.get(i + 1));
			}

			return new RoleHierarchyImpl(this.roleHierarchyBuilder.getRolesReachableInOneOrMoreStepsMap());
		}
	}

	public static RoleHierarchyBuilder builder() {
		return new RoleHierarchyBuilder();
	}
}
