/*
 * Copyright 2002-2024 the original author or authors.
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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.Assert;

/**
 * <p>
 * This class defines a role hierarchy for use with various access checking components.
 *
 * <p>
 * Here is an example configuration of a role hierarchy (hint: read the "&gt;" sign as
 * "includes"):
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
 * <li>In effect every user with ROLE_A also has ROLE_B, ROLE_AUTHENTICATED and
 * ROLE_UNAUTHENTICATED;</li>
 * <li>every user with ROLE_B also has ROLE_AUTHENTICATED and ROLE_UNAUTHENTICATED;</li>
 * <li>every user with ROLE_AUTHENTICATED also has ROLE_UNAUTHENTICATED.</li>
 * </ul>
 *
 * <p>
 * Hierarchical Roles will dramatically shorten your access rules (and also make the
 * access rules much more elegant).
 *
 * <p>
 * Consider this access rule for Spring Security's RoleVoter (background: every user that
 * is authenticated should be able to log out):
 * <pre>/logout.html=ROLE_A,ROLE_B,ROLE_AUTHENTICATED</pre>
 *
 * With hierarchical roles this can now be shortened to:
 * <pre>/logout.html=ROLE_AUTHENTICATED</pre>
 *
 * In addition to shorter rules this will also make your access rules more readable and
 * your intentions clearer.
 *
 * @author Michael Mayr
 * @author Josh Cummings
 */
public class RoleHierarchyImpl implements RoleHierarchy {

	private static final Log logger = LogFactory.getLog(RoleHierarchyImpl.class);

	/**
	 * {@code rolesReachableInOneOrMoreStepsMap} is a Map that under the key of a specific
	 * role name contains a set of all roles reachable from this role in 1 or more steps
	 */
	private Map<String, Set<GrantedAuthority>> rolesReachableInOneOrMoreStepsMap = null;

	/**
	 * @deprecated Use {@link RoleHierarchyImpl#fromHierarchy} instead
	 */
	@Deprecated
	public RoleHierarchyImpl() {

	}

	private RoleHierarchyImpl(Map<String, Set<GrantedAuthority>> hierarchy) {
		this.rolesReachableInOneOrMoreStepsMap = buildRolesReachableInOneOrMoreStepsMap(hierarchy);
	}

	/**
	 * Create a role hierarchy instance with the given definition, similar to the
	 * following:
	 *
	 * <pre>
	 *     ROLE_A &gt; ROLE_B
	 *     ROLE_B &gt; ROLE_AUTHENTICATED
	 *     ROLE_AUTHENTICATED &gt; ROLE_UNAUTHENTICATED
	 * </pre>
	 * @param hierarchy the role hierarchy to use
	 * @return a {@link RoleHierarchyImpl} that uses the given {@code hierarchy}
	 */
	public static RoleHierarchyImpl fromHierarchy(String hierarchy) {
		return new RoleHierarchyImpl(buildRolesReachableInOneStepMap(hierarchy));
	}

	/**
	 * Factory method that creates a {@link Builder} instance with the default role prefix
	 * "ROLE_"
	 * @return a {@link Builder} instance with the default role prefix "ROLE_"
	 * @since 6.3
	 */
	public static Builder withDefaultRolePrefix() {
		return withRolePrefix("ROLE_");
	}

	/**
	 * Factory method that creates a {@link Builder} instance with the specified role
	 * prefix.
	 * @param rolePrefix the prefix to be used for the roles in the hierarchy.
	 * @return a new {@link Builder} instance with the specified role prefix
	 * @throws IllegalArgumentException if the provided role prefix is null
	 * @since 6.3
	 */
	public static Builder withRolePrefix(String rolePrefix) {
		Assert.notNull(rolePrefix, "rolePrefix must not be null");
		return new Builder(rolePrefix);
	}

	/**
	 * Set the role hierarchy and pre-calculate for every role the set of all reachable
	 * roles, i.e. all roles lower in the hierarchy of every given role. Pre-calculation
	 * is done for performance reasons (reachable roles can then be calculated in O(1)
	 * time). During pre-calculation, cycles in role hierarchy are detected and will cause
	 * a <tt>CycleInRoleHierarchyException</tt> to be thrown.
	 * @param roleHierarchyStringRepresentation - String definition of the role hierarchy.
	 * @deprecated Use {@link RoleHierarchyImpl#fromHierarchy} instead
	 */
	@Deprecated
	public void setHierarchy(String roleHierarchyStringRepresentation) {
		logger.debug(LogMessage.format("setHierarchy() - The following role hierarchy was set: %s",
				roleHierarchyStringRepresentation));
		Map<String, Set<GrantedAuthority>> hierarchy = buildRolesReachableInOneStepMap(
				roleHierarchyStringRepresentation);
		this.rolesReachableInOneOrMoreStepsMap = buildRolesReachableInOneOrMoreStepsMap(hierarchy);
	}

	@Override
	public Collection<GrantedAuthority> getReachableGrantedAuthorities(
			Collection<? extends GrantedAuthority> authorities) {
		if (authorities == null || authorities.isEmpty()) {
			return AuthorityUtils.NO_AUTHORITIES;
		}
		Set<GrantedAuthority> reachableRoles = new HashSet<>();
		Set<String> processedNames = new HashSet<>();
		for (GrantedAuthority authority : authorities) {
			// Do not process authorities without string representation
			if (authority.getAuthority() == null) {
				reachableRoles.add(authority);
				continue;
			}
			// Do not process already processed roles
			if (!processedNames.add(authority.getAuthority())) {
				continue;
			}
			// Add original authority
			reachableRoles.add(authority);
			// Add roles reachable in one or more steps
			Set<GrantedAuthority> lowerRoles = this.rolesReachableInOneOrMoreStepsMap.get(authority.getAuthority());
			if (lowerRoles == null) {
				continue; // No hierarchy for the role
			}
			for (GrantedAuthority role : lowerRoles) {
				if (processedNames.add(role.getAuthority())) {
					reachableRoles.add(role);
				}
			}
		}
		logger.debug(LogMessage.format(
				"getReachableGrantedAuthorities() - From the roles %s one can reach %s in zero or more steps.",
				authorities, reachableRoles));
		return new ArrayList<>(reachableRoles);
	}

	/**
	 * Parse input and build the map for the roles reachable in one step: the higher role
	 * will become a key that references a set of the reachable lower roles.
	 */
	private static Map<String, Set<GrantedAuthority>> buildRolesReachableInOneStepMap(String hierarchy) {
		Map<String, Set<GrantedAuthority>> rolesReachableInOneStepMap = new HashMap<>();
		for (String line : hierarchy.split("\n")) {
			// Split on > and trim excessive whitespace
			String[] roles = line.trim().split("\\s+>\\s+");
			for (int i = 1; i < roles.length; i++) {
				String higherRole = roles[i - 1];
				GrantedAuthority lowerRole = new SimpleGrantedAuthority(roles[i]);
				Set<GrantedAuthority> rolesReachableInOneStepSet;
				if (!rolesReachableInOneStepMap.containsKey(higherRole)) {
					rolesReachableInOneStepSet = new HashSet<>();
					rolesReachableInOneStepMap.put(higherRole, rolesReachableInOneStepSet);
				}
				else {
					rolesReachableInOneStepSet = rolesReachableInOneStepMap.get(higherRole);
				}
				rolesReachableInOneStepSet.add(lowerRole);
				logger.debug(LogMessage.format(
						"buildRolesReachableInOneStepMap() - From role %s one can reach role %s in one step.",
						higherRole, lowerRole));
			}
		}
		return rolesReachableInOneStepMap;
	}

	/**
	 * For every higher role from rolesReachableInOneStepMap store all roles that are
	 * reachable from it in the map of roles reachable in one or more steps. (Or throw a
	 * CycleInRoleHierarchyException if a cycle in the role hierarchy definition is
	 * detected)
	 */
	private static Map<String, Set<GrantedAuthority>> buildRolesReachableInOneOrMoreStepsMap(
			Map<String, Set<GrantedAuthority>> hierarchy) {
		Map<String, Set<GrantedAuthority>> rolesReachableInOneOrMoreStepsMap = new HashMap<>();
		// iterate over all higher roles from rolesReachableInOneStepMap
		for (String roleName : hierarchy.keySet()) {
			Set<GrantedAuthority> rolesToVisitSet = new HashSet<>(hierarchy.get(roleName));
			Set<GrantedAuthority> visitedRolesSet = new HashSet<>();
			while (!rolesToVisitSet.isEmpty()) {
				// take a role from the rolesToVisit set
				GrantedAuthority lowerRole = rolesToVisitSet.iterator().next();
				rolesToVisitSet.remove(lowerRole);
				if (!visitedRolesSet.add(lowerRole) || !hierarchy.containsKey(lowerRole.getAuthority())) {
					continue; // Already visited role or role with missing hierarchy
				}
				else if (roleName.equals(lowerRole.getAuthority())) {
					throw new CycleInRoleHierarchyException();
				}
				rolesToVisitSet.addAll(hierarchy.get(lowerRole.getAuthority()));
			}
			rolesReachableInOneOrMoreStepsMap.put(roleName, visitedRolesSet);
			logger.debug(LogMessage.format(
					"buildRolesReachableInOneOrMoreStepsMap() - From role %s one can reach %s in one or more steps.",
					roleName, visitedRolesSet));
		}
		return rolesReachableInOneOrMoreStepsMap;
	}

	/**
	 * Builder class for constructing a {@link RoleHierarchyImpl} based on a hierarchical
	 * role structure.
	 *
	 * @author Federico Herrera
	 * @since 6.3
	 */
	public static final class Builder {

		private final String rolePrefix;

		private final Map<String, Set<GrantedAuthority>> hierarchy;

		private Builder(String rolePrefix) {
			this.rolePrefix = rolePrefix;
			this.hierarchy = new LinkedHashMap<>();
		}

		/**
		 * Creates a new hierarchy branch to define a role and its child roles.
		 * @param role the highest role in this branch
		 * @return a {@link ImpliedRoles} to define the child roles for the
		 * <code>role</code>
		 */
		public ImpliedRoles role(String role) {
			Assert.hasText(role, "role must not be empty");
			return new ImpliedRoles(role);
		}

		/**
		 * Builds and returns a {@link RoleHierarchyImpl} describing the defined role
		 * hierarchy.
		 * @return a {@link RoleHierarchyImpl}
		 */
		public RoleHierarchyImpl build() {
			return new RoleHierarchyImpl(this.hierarchy);
		}

		private Builder addHierarchy(String role, String... impliedRoles) {
			Set<GrantedAuthority> withPrefix = this.hierarchy.computeIfAbsent(this.rolePrefix.concat(role),
					(r) -> new HashSet<>());
			for (String impliedRole : impliedRoles) {
				withPrefix.add(new SimpleGrantedAuthority(this.rolePrefix.concat(impliedRole)));
			}
			return this;
		}

		/**
		 * Builder class for constructing child roles within a role hierarchy branch.
		 */
		public final class ImpliedRoles {

			private final String role;

			private ImpliedRoles(String role) {
				this.role = role;
			}

			/**
			 * Specifies implied role(s) for the current role in the hierarchy.
			 * @param impliedRoles role name(s) implied by the role.
			 * @return the same {@link Builder} instance
			 * @throws IllegalArgumentException if <code>impliedRoles</code> is null,
			 * empty or contains any null element.
			 */
			public Builder implies(String... impliedRoles) {
				Assert.notEmpty(impliedRoles, "at least one implied role must be provided");
				Assert.noNullElements(impliedRoles, "implied role name(s) cannot be empty");
				return Builder.this.addHierarchy(this.role, impliedRoles);
			}

		}

	}

}
