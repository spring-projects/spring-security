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
package org.springframework.security.access.vote;

import org.junit.Test;

import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.TestingAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;

public class RoleHierarchyVoterTests {

	@Test
	public void hierarchicalRoleIsIncludedInDecision() {
		RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();
		roleHierarchyImpl.setHierarchy("ROLE_A > ROLE_B");

		// User has role A, role B is required
		TestingAuthenticationToken auth = new TestingAuthenticationToken("user", "password", "ROLE_A");
		RoleHierarchyVoter voter = new RoleHierarchyVoter(roleHierarchyImpl);

		assertThat(voter.vote(auth, new Object(), SecurityConfig.createList("ROLE_B")))
				.isEqualTo(RoleHierarchyVoter.ACCESS_GRANTED);
	}

}
