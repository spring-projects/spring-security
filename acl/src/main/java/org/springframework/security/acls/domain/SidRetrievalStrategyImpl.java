/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.acls.domain;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.access.hierarchicalroles.NullRoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.model.SidRetrievalStrategy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

/**
 * Basic implementation of {@link SidRetrievalStrategy} that creates a {@link Sid} for the
 * principal, as well as every granted authority the principal holds. Can optionally have
 * a <tt>RoleHierarchy</tt> injected in order to determine the extended list of
 * authorities that the principal is assigned.
 * <p>
 * The returned array will always contain the {@link PrincipalSid} before any
 * {@link GrantedAuthoritySid} elements.
 *
 * @author Ben Alex
 */
public class SidRetrievalStrategyImpl implements SidRetrievalStrategy {

	private RoleHierarchy roleHierarchy = new NullRoleHierarchy();

	public SidRetrievalStrategyImpl() {
	}

	public SidRetrievalStrategyImpl(RoleHierarchy roleHierarchy) {
		Assert.notNull(roleHierarchy, "RoleHierarchy must not be null");
		this.roleHierarchy = roleHierarchy;
	}

	// ~ Methods
	// ========================================================================================================

	public List<Sid> getSids(Authentication authentication) {
		Collection<? extends GrantedAuthority> authorities = roleHierarchy
				.getReachableGrantedAuthorities(authentication.getAuthorities());
		List<Sid> sids = new ArrayList<>(authorities.size() + 1);

		sids.add(new PrincipalSid(authentication));

		for (GrantedAuthority authority : authorities) {
			sids.add(new GrantedAuthoritySid(authority));
		}

		return sids;
	}

}
