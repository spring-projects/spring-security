/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.acegisecurity.userdetails.hierarchicalroles;


import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.util.*;

/**
 * <p>
 * This class defines a role hierarchy for use with the UserDetailsServiceWrapper.
 * </p>
 * <p>
 * Here is an example configuration of a role hierarchy (hint: read the "&gt;" sign as "includes"):
<pre>
        &lt;property name="hierarchy"&gt;
            &lt;value&gt;
                ROLE_A &gt; ROLE_B
                ROLE_B &gt; ROLE_AUTHENTICATED
                ROLE_AUTHENTICATED &gt; ROLE_UNAUTHENTICATED
            &lt;/value&gt;
        &lt;/property&gt;
</pre>
</p>
 * <p>
 * Explanation of the above:<br>
 * In effect every user with ROLE_A also has ROLE_B, ROLE_AUTHENTICATED and ROLE_UNAUTHENTICATED;<br>
 * every user with ROLE_B also has ROLE_AUTHENTICATED and ROLE_UNAUTHENTICATED;<br>
 * every user with ROLE_AUTHENTICATED also has ROLE_UNAUTHENTICATED.
 * </p>
 * <p>
 * Hierarchical Roles will dramatically shorten your access rules (and also make the access rules much more elegant).
 * </p>
 * <p>
 * Consider this access rule for Acegi's RoleVoter (background: every user that is authenticated should be
 * able to log out):<br>
 * /logout.html=ROLE_A,ROLE_B,ROLE_AUTHENTICATED<br>
 * With hierarchical roles this can now be shortened to:<br>
 * /logout.html=ROLE_AUTHENTICATED<br>
 * In addition to shorter rules this will also make your access rules more readable and your intentions clearer.
 * </p>
 *
 * @author Michael Mayr
 *
 */
public class RoleHierarchyImpl implements RoleHierarchy {

    private static final Log logger = LogFactory.getLog(RoleHierarchyImpl.class);

    private String roleHierarchyStringRepresentation = null;

    /**
     * rolesReachableInOneStepMap is a Map that under the key of a specific role name contains a set of all roles
     * reachable from this role in 1 step
     */
    private Map rolesReachableInOneStepMap = null;

    /**
     * rolesReachableInOneOrMoreStepsMap is a Map that under the key of a specific role name contains a set of all
     * roles reachable from this role in 1 or more steps
     */
    private Map rolesReachableInOneOrMoreStepsMap = null;

    /**
     * Set the role hierarchy and precalculate for every role the set of all reachable roles, i. e. all roles lower in
     * the hierarchy of every given role. Precalculation is done for performance reasons (reachable roles can then be
     * calculated in O(1) time).
     * During precalculation cycles in role hierarchy are detected and will cause a
     * <tt>CycleInRoleHierarchyException</tt> to be thrown.
     *
     * @param roleHierarchyStringRepresentation - String definition of the role hierarchy.
     */
    public void setHierarchy(String roleHierarchyStringRepresentation) {
        this.roleHierarchyStringRepresentation = roleHierarchyStringRepresentation;

        logger.debug("setHierarchy() - The following role hierarchy was set: " + roleHierarchyStringRepresentation);

        buildRolesReachableInOneStepMap();
        buildRolesReachableInOneOrMoreStepsMap();
    }

    public GrantedAuthority[] getReachableGrantedAuthorities(GrantedAuthority[] authorities) {
        if (authorities == null || authorities.length == 0) {
            return null;
        }

        Set reachableRoles = new HashSet();

        for (int i = 0; i < authorities.length; i++) {
            reachableRoles.add(authorities[i]);
            Set additionalReachableRoles = (Set) rolesReachableInOneOrMoreStepsMap.get(authorities[i]);
            if (additionalReachableRoles != null) {
                reachableRoles.addAll(additionalReachableRoles);
            }
        }

        if (logger.isDebugEnabled()) {
            logger.debug("getReachableGrantedAuthorities() - From the roles " + Arrays.asList(authorities)
                    + " one can reach " + reachableRoles + " in zero or more steps.");
        }

        return (GrantedAuthority[]) reachableRoles.toArray(new GrantedAuthority[reachableRoles.size()]);
    }

    /**
     * Parse input and build the map for the roles reachable in one step: the higher role will become a key that
     * references a set of the reachable lower roles.
     */
    private void buildRolesReachableInOneStepMap() {
        String parsingRegex = "(\\s*(\\w+)\\s*\\>\\s*(\\w+))";
        Pattern pattern = Pattern.compile(parsingRegex);

        Matcher roleHierarchyMatcher = pattern.matcher(roleHierarchyStringRepresentation);
        rolesReachableInOneStepMap = new HashMap();

        while (roleHierarchyMatcher.find()) {
            GrantedAuthority higherRole = new GrantedAuthorityImpl(roleHierarchyMatcher.group(2));
            GrantedAuthority lowerRole = new GrantedAuthorityImpl(roleHierarchyMatcher.group(3));
            Set rolesReachableInOneStepSet = null;

            if (!rolesReachableInOneStepMap.containsKey(higherRole)) {
                rolesReachableInOneStepSet = new HashSet();
                rolesReachableInOneStepMap.put(higherRole, rolesReachableInOneStepSet);
            } else {
                rolesReachableInOneStepSet = (Set) rolesReachableInOneStepMap.get(higherRole);
            }
            rolesReachableInOneStepSet.add(lowerRole);

            logger.debug("buildRolesReachableInOneStepMap() - From role "
                    + higherRole + " one can reach role " + lowerRole + " in one step.");
        }
    }

    /**
     * For every higher role from rolesReachableInOneStepMap store all roles that are reachable from it in the map of
     * roles reachable in one or more steps. (Or throw a CycleInRoleHierarchyException if a cycle in the role
     * hierarchy definition is detected)
     */
    private void buildRolesReachableInOneOrMoreStepsMap() {
        rolesReachableInOneOrMoreStepsMap = new HashMap();
        // iterate over all higher roles from rolesReachableInOneStepMap
        Iterator roleIterator = rolesReachableInOneStepMap.keySet().iterator();

        while (roleIterator.hasNext()) {
            GrantedAuthority role = (GrantedAuthority) roleIterator.next();
            Set rolesToVisitSet = new HashSet();

            if (rolesReachableInOneStepMap.containsKey(role)) {
                rolesToVisitSet.addAll((Set) rolesReachableInOneStepMap.get(role));
            }

            Set visitedRolesSet = new HashSet();

            while (!rolesToVisitSet.isEmpty()) {
                // take a role from the rolesToVisit set
                GrantedAuthority aRole = (GrantedAuthority) rolesToVisitSet.iterator().next();
                rolesToVisitSet.remove(aRole);
                visitedRolesSet.add(aRole);
                if (rolesReachableInOneStepMap.containsKey(aRole)) {
                    Set newReachableRoles = (Set) rolesReachableInOneStepMap.get(aRole);

                    // definition of a cycle: you can reach the role you are starting from
                    if (rolesToVisitSet.contains(role) || visitedRolesSet.contains(role)) {
                        throw new CycleInRoleHierarchyException();
                    } else {
                         // no cycle
                        rolesToVisitSet.addAll(newReachableRoles);
                    }
                }
            }
            rolesReachableInOneOrMoreStepsMap.put(role, visitedRolesSet);

            logger.debug("buildRolesReachableInOneOrMoreStepsMap() - From role "
                    + role + " one can reach " + visitedRolesSet + " in one or more steps.");
        }

    }

}
