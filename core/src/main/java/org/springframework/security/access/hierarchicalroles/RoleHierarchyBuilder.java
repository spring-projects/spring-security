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
 * Builder for {@link RoleHierarchyImpl}, which is the default implementation of {@link RoleHierarchy}
 *
 * <p>
 * Example:
 * <pre>
 *     RoleHierarchy roleHierarchy = RoleHierarchyBuilder
 * 		.builder()
 * 		.role(ROLE_A)
 * 			.includes(ROLE_B)
 * 			.whichIncludes(ROLE_C)
 * 			.and()
 * 		.role(ROLE_A)
 * 			.includes(ROLE_D)
 * 			.whichIncludes(ROLE_E)
 * 			.and()
 * 		.role(ROLE_D)
 * 			.includes(ROLE_F)
 * 			.build();
 * </pre>
 * </p>
 *
 * The visual representation of this would be like this:
 * <pre>
 *
 *                             ROLE_A
 *                             /    \
 *                            /      \
 *                           -        -
 *                        ROLE_B    ROLE_D -------------+
 *                         /            \               |
 *                        /              \              |
 *                       -                -             |
 *                    ROLE_C            ROLE_E       ROLE_F
 *
 * </pre>
 *
 * With this is effect, a user with ROLE_A will inherently have all the other roles included, while for example a
 * user with ROLE_D will also have roles ROLE_E and ROLE_F
 *
 * <p>
 * @see RoleHierarchyImpl
 * @author Sebastijan Grabar
 */
public class RoleHierarchyBuilder {

	private final Map<String, Set<GrantedAuthority>> rolesReachableInOneStepMap = new HashMap<>();

	private RoleHierarchyBuilder() {
	}

	/**
	 * @return a new {@link RoleHierarchyBuilder} instance
	 */
	public static RoleHierarchyBuilder builder() {
		return new RoleHierarchyBuilder();
	}

	/**
	 * @param role_1 role to initialize the the builder tree branch with
	 * @return builder with {@code role_1} as the base to build one branch on the role hierarchy tree
	 */
	public FirstRoleBuilder role(String role_1) {
		return new FirstRoleBuilder(role_1, this);
	}

	/**
	 * Adds {@code nextReachableRole} to the map with roles that {@code currStep} can reach in one step
	 *
	 * @param currRole
	 * @param nextReachableRole
	 */
	private void addReachableRole(String currRole, String nextReachableRole) {
		Set<GrantedAuthority> reachableRoles = rolesReachableInOneStepMap
				.getOrDefault(currRole, new HashSet<>());

		reachableRoles
				.add(new SimpleGrantedAuthority(nextReachableRole));

		rolesReachableInOneStepMap
				.put(currRole, reachableRoles);
	}

	/**
	 * The base class for {@link FirstRoleBuilder} and {@link NextRoleBuilder}, so they can both call
	 * the {@link BaseRoleBuilder#build()} method, which returns a {@link RoleHierarchyImpl} instance
	 */
	private static abstract class BaseRoleBuilder {
		private final RoleHierarchyBuilder roleHierarchyBuilder;

		BaseRoleBuilder(RoleHierarchyBuilder roleHierarchyBuilder) {
			this.roleHierarchyBuilder = roleHierarchyBuilder;
		}

		/**
		 * Terminates the builder and returns a new {@link RoleHierarchyImpl} instance, with the hierarchy that
		 * was specified by calling the methods of the builder
		 * @return a new instance of {@link RoleHierarchyImpl}
		 */
		public RoleHierarchy build() {
			return new RoleHierarchyImpl(this.roleHierarchyBuilder.rolesReachableInOneStepMap);
		}
	}

	/**
	 * The class whose instance is returned only by the {@link RoleHierarchyBuilder#builder()} method, so that
	 * the consecutive call to {@link NextRoleBuilder#whichIncludes(String role)} can emphasize that it is
	 * referring to the role was used in the previous {@link FirstRoleBuilder#includes(String role)} method call and
	 * not the role used in the call to the {@link RoleHierarchyBuilder#role(String role)} method
	 */
	public static class FirstRoleBuilder extends BaseRoleBuilder {

		private final String currRole;
		private final RoleHierarchyBuilder roleHierarchyBuilder;

		private FirstRoleBuilder(String role_1, RoleHierarchyBuilder roleHierarchyBuilder) {
			super(roleHierarchyBuilder);
			this.currRole = role_1;
			this.roleHierarchyBuilder = roleHierarchyBuilder;
		}

		/**
		 * @see NextRoleBuilder#whichIncludes(String role)
		 * @param role_2 role to include in the tree branch that the class was called upon
		 * @return {@link NextRoleBuilder} for further chaining
		 */
		public NextRoleBuilder includes(String role_2) {
			roleHierarchyBuilder.addReachableRole(currRole, role_2);
			return new NextRoleBuilder(role_2, roleHierarchyBuilder);
		}
	}

	/**
	 * The class whose instance is returned by the {@link FirstRoleBuilder#includes} and the
	 * {@link NextRoleBuilder#whichIncludes} methods, to enable further method chaining
	 */
	public static class NextRoleBuilder extends BaseRoleBuilder {

		private final String currRole;
		private final RoleHierarchyBuilder roleHierarchyBuilder;

		private NextRoleBuilder(String role_1, RoleHierarchyBuilder roleHierarchyBuilder) {
			super(roleHierarchyBuilder);
			this.currRole = role_1;
			this.roleHierarchyBuilder = roleHierarchyBuilder;
		}

		/**
		 * @param role_2 role to include in the tree branch that the class was called upon
		 * @see FirstRoleBuilder#includes(String role)
		 * @return {@link NextRoleBuilder} for further chaining
		 */
		public NextRoleBuilder whichIncludes(String role_2) {
			roleHierarchyBuilder.addReachableRole(currRole, role_2);
			return new NextRoleBuilder(role_2, roleHierarchyBuilder);
		}

		/**
		 * @return the same instance of {@link RoleHierarchyBuilder}, so that another branch of hierarchy can be added,
		 * separate from this one, through the {@link RoleHierarchyBuilder#role(String role)} method
		 */
		public RoleHierarchyBuilder and() {
			return roleHierarchyBuilder;
		}
	}
}
