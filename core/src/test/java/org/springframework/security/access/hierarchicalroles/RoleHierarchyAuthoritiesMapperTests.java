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

import org.junit.Test;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Luke Taylor
 */
public class RoleHierarchyAuthoritiesMapperTests {

	@Test
	public void expectedAuthoritiesAreReturned() {
		RoleHierarchyImpl rh = new RoleHierarchyImpl();
		rh.setHierarchy("ROLE_A > ROLE_B\nROLE_B > ROLE_C");
		RoleHierarchyAuthoritiesMapper mapper = new RoleHierarchyAuthoritiesMapper(rh);

		Collection<? extends GrantedAuthority> authorities = mapper
				.mapAuthorities(AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_D"));

		assertThat(authorities).hasSize(4);

		mapper = new RoleHierarchyAuthoritiesMapper(new NullRoleHierarchy());

		authorities = mapper.mapAuthorities(AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_D"));

		assertThat(authorities).hasSize(2);
	}

}
