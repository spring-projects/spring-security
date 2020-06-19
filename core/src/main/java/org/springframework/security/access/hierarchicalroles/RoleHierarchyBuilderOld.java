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
 * <p>
 * This class defines a role hierarchy for use with various access checking components.
 *
 * <p>
 * Here is an example configuration of a role hierarchy (hint: read the "&gt;" sign as "includes"):
 *
 * <pre>
 *     &lt;property name="hierarchy"&gt;
 *         &lt;value&gt;
 *             ROLE_A &gt; ROLE_B
 *             ROLE_B &gt; ROLE_AUTHENTICATED
 *             ROLE_AUTHENTICATED &gt; ROLE_UNAUTHENTICATED
 *         &lt;/value&gt;
 *     &lt;/property&gt;
 * </pre>
 *
 * <p>
 * Explanation of the above:
 * <ul>
 * <li>In effect every user with ROLE_A also has ROLE_B, ROLE_AUTHENTICATED and ROLE_UNAUTHENTICATED;</li>
 * <li>every user with ROLE_B also has ROLE_AUTHENTICATED and ROLE_UNAUTHENTICATED;</li>
 * <li>every user with ROLE_AUTHENTICATED also has ROLE_UNAUTHENTICATED.</li>
 * </ul>
 *
 * <p>
 * Hierarchical Roles will dramatically shorten your access rules (and also make the access rules
 * much more elegant).
 *
 * <p>
 * Consider this access rule for Spring Security's RoleVoter (background: every user that is
 * authenticated should be able to log out):
 * <pre>/logout.html=ROLE_A,ROLE_B,ROLE_AUTHENTICATED</pre>
 * <p>
 * With hierarchical roles this can now be shortened to:
 * <pre>/logout.html=ROLE_AUTHENTICATED</pre>
 * <p>
 * In addition to shorter rules this will also make your access rules more readable and your
 * intentions clearer.
 *
 * @author Michael Mayr
 */
public class RoleHierarchyBuilderOld {
	private final Map<String, Set<GrantedAuthority>> rolesReachableInOneOrMoreStepsMap = new HashMap<>();

	private RoleHierarchyBuilderOld() {
	}

	public CurrRole role(String role_1) {
		return new CurrRole(null, role_1, this);
	}

	private void addReachableRole(String parentRole, String currRole, String reachableRole) {


		if (!rolesReachableInOneOrMoreStepsMap.containsKey(currRole)) {
			Set<GrantedAuthority> reachableRoles = new HashSet<>();
			reachableRoles
					.add(new SimpleGrantedAuthority(reachableRole));

			rolesReachableInOneOrMoreStepsMap
					.put(currRole, reachableRoles);
		} else {
			rolesReachableInOneOrMoreStepsMap
					.get(currRole)
					.add(new SimpleGrantedAuthority(reachableRole));
		}

		if (parentRole != null) {
			Set<GrantedAuthority> rolesForCurrRole = rolesReachableInOneOrMoreStepsMap
					.get(currRole);

			rolesReachableInOneOrMoreStepsMap
					.get(parentRole)
					.addAll(rolesForCurrRole);
		}

	}

	private Map<String, Set<GrantedAuthority>> getRolesReachableInOneOrMoreStepsMap() {
		return Collections.unmodifiableMap(this.rolesReachableInOneOrMoreStepsMap);
	}


	public static class CurrRole {

		private final String parentRole;
		private final String currRole;
		private final RoleHierarchyBuilderOld roleHierarchyBuilderOld;

		private CurrRole(String parentRole, String role_1, RoleHierarchyBuilderOld roleHierarchyBuilderOld) {
			this.currRole = role_1;
			this.roleHierarchyBuilderOld = roleHierarchyBuilderOld;
			this.parentRole = parentRole;
		}

		public CurrRole includes(String role_2) {
			roleHierarchyBuilderOld.addReachableRole(parentRole, currRole, role_2);
			return new CurrRole(currRole, role_2, roleHierarchyBuilderOld);
		}

		public RoleHierarchyBuilderOld and() {
			return roleHierarchyBuilderOld;
		}

		public RoleHierarchy build() {
			return new RoleHierarchyImpl(this.roleHierarchyBuilderOld.getRolesReachableInOneOrMoreStepsMap());
		}
	}

	public static RoleHierarchyBuilderOld builder() {
		return new RoleHierarchyBuilderOld();
	}
}
