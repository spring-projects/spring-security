/*
 * Copyright 2002-2016 the original author or authors.
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

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;

/**
 * The simple interface of a role hierarchy.
 *
 * @author Michael Mayr
 */
public interface RoleHierarchy {

	/**
	 * Returns an array of all reachable authorities.
	 * <p>
	 * Reachable authorities are the directly assigned authorities plus all authorities
	 * that are (transitively) reachable from them in the role hierarchy.
	 * <p>
	 * Example:<br>
	 * Role hierarchy: ROLE_A &gt; ROLE_B and ROLE_B &gt; ROLE_C.<br>
	 * Directly assigned authority: ROLE_A.<br>
	 * Reachable authorities: ROLE_A, ROLE_B, ROLE_C.
	 *
	 * @param authorities - List of the directly assigned authorities.
	 * @return List of all reachable authorities given the assigned authorities.
	 */
	public Collection<? extends GrantedAuthority> getReachableGrantedAuthorities(
			Collection<? extends GrantedAuthority> authorities);

}
