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

package org.springframework.security.access.hierarchicalroles;

import java.util.List;

import org.springframework.security.GrantedAuthority;

/**
 * The simple interface of a role hierarchy.
 *
 * @author Michael Mayr
 *
 */
public interface RoleHierarchy {

    /**
     * This method returns an array of all reachable authorities.<br>
     * Reachable authorities are the directly assigned authorities plus all
     * authorities that are (transitively) reachable from them in the role
     * hierarchy.<br>
     * Example:<br>
     * Role hierarchy: ROLE_A > ROLE_B and ROLE_B > ROLE_C.<br>
     * Directly assigned authority: ROLE_A.<br>
     * Reachable authorities: ROLE_A, ROLE_B, ROLE_C.
     *
     * @param authorities - Array of the directly assigned authorities.
     * @return Array of all reachable authorities given the assigned authorities.
     */
    public List<GrantedAuthority> getReachableGrantedAuthorities(List<GrantedAuthority> authorities);

}
