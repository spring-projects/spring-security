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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
public class RoleHierarchyImpl implements RoleHierarchy {

	private static final Log logger = LogFactory.getLog(RoleHierarchyImpl.class);

	/**
	 * {@code rolesReachableInOneOrMoreStepsMap} is a Map that under the key of a specific role
	 * name contains a set of all roles reachable from this role in 1 or more steps
	 */
	private Map<String, Set<GrantedAuthority>> rolesReachableInOneOrMoreStepsMap = null;

	public RoleHierarchyImpl() {
	}

	protected RoleHierarchyImpl(Map<String, Set<GrantedAuthority>> rolesReachableInOneStepMap) {
		this.rolesReachableInOneOrMoreStepsMap = buildRolesReachableInOneOrMoreStepsMap(rolesReachableInOneStepMap);
	}

	/**
	 * Set the role hierarchy and pre-calculate for every role the set of all reachable
	 * roles, i.e. all roles lower in the hierarchy of every given role. Pre-calculation
	 * is done for performance reasons (reachable roles can then be calculated in O(1)
	 * time). During pre-calculation, cycles in role hierarchy are detected and will cause
	 * a <tt>CycleInRoleHierarchyException</tt> to be thrown.
	 *
	 * @param roleHierarchyStringRepresentation - String definition of the role hierarchy.
	 */
	public void setHierarchy(String roleHierarchyStringRepresentation) {
		if (logger.isDebugEnabled()) {
			logger.debug("setHierarchy() - The following role hierarchy was set: "
					+ roleHierarchyStringRepresentation);
		}

		Map<String, Set<GrantedAuthority>> rolesReachableInOneStepMap = buildRolesReachableInOneStepMap(roleHierarchyStringRepresentation);
		this.rolesReachableInOneOrMoreStepsMap = buildRolesReachableInOneOrMoreStepsMap(rolesReachableInOneStepMap);
	}

	@Override
	public Collection<GrantedAuthority> getReachableGrantedAuthorities(
			Collection<? extends GrantedAuthority> authorities) {
		if (authorities == null || authorities.isEmpty()) {
			return AuthorityUtils.NO_AUTHORITIES;
		}

		Set<String> processedNames = new HashSet<>();

		List<GrantedAuthority> reachableRoleList = authorities
				.stream()
				.filter(authority -> processedNames.add(authority.getAuthority())) // Skip already added authorities
				.flatMap(authority -> {
					if (authority.getAuthority() == null) { // Skip authorities without string representation
						return Stream.of(authority);
					}

					return Stream.concat(
							Stream.of(authority), // Add original authority
							this.rolesReachableInOneOrMoreStepsMap // Add authorities reachable in one or more steps
									.getOrDefault(authority.getAuthority(), new HashSet<>())
									.stream()
									.filter(role -> processedNames.add(role.getAuthority())) // Skip already added authorities
					);
				})
				.collect(Collectors.toList());

		if (logger.isDebugEnabled()) {
			logger.debug("getReachableGrantedAuthorities() - From the roles "
					+ authorities + " one can reach " + reachableRoleList
					+ " in zero or more steps.");
		}

		return reachableRoleList;
	}

	/**
	 * Parse input and build the map for the roles reachable in one step: the higher role
	 * will become a key that references a set of the reachable lower roles.
	 *
	 * @return
	 */
	private Map<String, Set<GrantedAuthority>> buildRolesReachableInOneStepMap(String roleHierarchyStringRepresentation) {
		Map<String, Set<GrantedAuthority>> rolesReachableInOneStepMap = new HashMap<>();

		for (String line : roleHierarchyStringRepresentation.split("\n")) {
			// Split on > and trim excessive whitespace
			String[] roles = line.trim().split("\\s+>\\s+");

			for (int i = 1; i < roles.length; i++) {
				String higherRole = roles[i - 1];
				GrantedAuthority lowerRole = new SimpleGrantedAuthority(roles[i]);

				Set<GrantedAuthority> rolesReachableInOneStepSet;
				if (!rolesReachableInOneStepMap.containsKey(higherRole)) {
					rolesReachableInOneStepSet = new HashSet<>();
					rolesReachableInOneStepMap.put(higherRole, rolesReachableInOneStepSet);
				} else {
					rolesReachableInOneStepSet = rolesReachableInOneStepMap.get(higherRole);
				}
				rolesReachableInOneStepSet.add(lowerRole);

				if (logger.isDebugEnabled()) {
					logger.debug("buildRolesReachableInOneStepMap() - From role " + higherRole
							+ " one can reach role " + lowerRole + " in one step.");
				}
			}
		}

		return rolesReachableInOneStepMap;
	}

	/**
	 * For every higher role from rolesReachableInOneStepMap store all roles that are
	 * reachable from it in the map of roles reachable in one or more steps. (Or throw a
	 * CycleInRoleHierarchyException if a cycle in the role hierarchy definition is
	 * detected)
	 *
	 * @param rolesReachableInOneStepMap
	 */
	private Map<String, Set<GrantedAuthority>> buildRolesReachableInOneOrMoreStepsMap(Map<String, Set<GrantedAuthority>> rolesReachableInOneStepMap) {
		Map<String, Set<GrantedAuthority>> rolesReachableInOneOrMoreStepsMap = new HashMap<>();

		// iterate over all higher roles from rolesReachableInOneStepMap
		for (String roleName : rolesReachableInOneStepMap.keySet()) {
			Set<GrantedAuthority> rolesToVisitSet = new HashSet<>(rolesReachableInOneStepMap.get(roleName));
			Set<GrantedAuthority> visitedRolesSet = new HashSet<>();

			while (!rolesToVisitSet.isEmpty()) {
				// take a role from the rolesToVisit set
				GrantedAuthority lowerRole = rolesToVisitSet.iterator().next();
				rolesToVisitSet.remove(lowerRole);
				if (!visitedRolesSet.add(lowerRole) ||
						!rolesReachableInOneStepMap.containsKey(lowerRole.getAuthority())) {
					continue; // Already visited role or role with missing hierarchy
				} else if (roleName.equals(lowerRole.getAuthority())) {
					throw new CycleInRoleHierarchyException();
				}
				rolesToVisitSet.addAll(rolesReachableInOneStepMap.get(lowerRole.getAuthority()));
			}
			rolesReachableInOneOrMoreStepsMap.put(roleName, visitedRolesSet);

			logger.debug("buildRolesReachableInOneOrMoreStepsMap() - From role " + roleName
					+ " one can reach " + visitedRolesSet + " in one or more steps.");
		}

		return rolesReachableInOneOrMoreStepsMap;

	}

}
