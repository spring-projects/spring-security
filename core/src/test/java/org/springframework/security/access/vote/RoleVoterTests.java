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

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Luke Taylor
 */
public class RoleVoterTests {

	@Test
	public void oneMatchingAttributeGrantsAccess() {
		RoleVoter voter = new RoleVoter();
		voter.setRolePrefix("");
		Authentication userAB = new TestingAuthenticationToken("user", "pass", "A", "B");
		// Vote on attribute list that has two attributes A and C (i.e. only one matching)
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("A", "C")))
				.isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
	}

	// SEC-3128
	@Test
	public void nullAuthenticationDenies() {
		RoleVoter voter = new RoleVoter();
		voter.setRolePrefix("");
		Authentication notAuthenitcated = null;
		assertThat(voter.vote(notAuthenitcated, this, SecurityConfig.createList("A")))
				.isEqualTo(AccessDecisionVoter.ACCESS_DENIED);
	}

}
