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

package org.springframework.security.access.vote;

import java.util.List;
import java.util.Vector;

import org.junit.Test;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.authentication.TestingAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Tests {@link UnanimousBased}.
 *
 * @author Ben Alex
 */
public class UnanimousBasedTests {

	private UnanimousBased makeDecisionManager() {
		RoleVoter roleVoter = new RoleVoter();
		DenyVoter denyForSureVoter = new DenyVoter();
		DenyAgainVoter denyAgainForSureVoter = new DenyAgainVoter();
		List<AccessDecisionVoter<? extends Object>> voters = new Vector<>();
		voters.add(roleVoter);
		voters.add(denyForSureVoter);
		voters.add(denyAgainForSureVoter);
		return new UnanimousBased(voters);
	}

	private UnanimousBased makeDecisionManagerWithFooBarPrefix() {
		RoleVoter roleVoter = new RoleVoter();
		roleVoter.setRolePrefix("FOOBAR_");
		DenyVoter denyForSureVoter = new DenyVoter();
		DenyAgainVoter denyAgainForSureVoter = new DenyAgainVoter();
		List<AccessDecisionVoter<? extends Object>> voters = new Vector<>();
		voters.add(roleVoter);
		voters.add(denyForSureVoter);
		voters.add(denyAgainForSureVoter);
		return new UnanimousBased(voters);
	}

	private TestingAuthenticationToken makeTestToken() {
		return new TestingAuthenticationToken("somebody", "password", "ROLE_1", "ROLE_2");
	}

	private TestingAuthenticationToken makeTestTokenWithFooBarPrefix() {
		return new TestingAuthenticationToken("somebody", "password", "FOOBAR_1", "FOOBAR_2");
	}

	@Test
	public void testOneAffirmativeVoteOneDenyVoteOneAbstainVoteDeniesAccess() {
		TestingAuthenticationToken auth = makeTestToken();
		UnanimousBased mgr = makeDecisionManager();
		List<ConfigAttribute> config = SecurityConfig.createList(new String[] { "ROLE_1", "DENY_FOR_SURE" });
		try {
			mgr.decide(auth, new Object(), config);
			fail("Should have thrown AccessDeniedException");
		}
		catch (AccessDeniedException expected) {
		}
	}

	@Test
	public void testOneAffirmativeVoteTwoAbstainVotesGrantsAccess() {
		TestingAuthenticationToken auth = makeTestToken();
		UnanimousBased mgr = makeDecisionManager();
		List<ConfigAttribute> config = SecurityConfig.createList("ROLE_2");
		mgr.decide(auth, new Object(), config);
	}

	@Test
	public void testOneDenyVoteTwoAbstainVotesDeniesAccess() {
		TestingAuthenticationToken auth = makeTestToken();
		UnanimousBased mgr = makeDecisionManager();
		List<ConfigAttribute> config = SecurityConfig.createList("ROLE_WE_DO_NOT_HAVE");
		try {
			mgr.decide(auth, new Object(), config);
			fail("Should have thrown AccessDeniedException");
		}
		catch (AccessDeniedException expected) {
		}
	}

	@Test
	public void testRoleVoterPrefixObserved() {
		TestingAuthenticationToken auth = makeTestTokenWithFooBarPrefix();
		UnanimousBased mgr = makeDecisionManagerWithFooBarPrefix();
		List<ConfigAttribute> config = SecurityConfig.createList(new String[] { "FOOBAR_1", "FOOBAR_2" });
		mgr.decide(auth, new Object(), config);
	}

	@Test
	public void testThreeAbstainVotesDeniesAccessWithDefault() {
		TestingAuthenticationToken auth = makeTestToken();
		UnanimousBased mgr = makeDecisionManager();
		assertThat(!mgr.isAllowIfAllAbstainDecisions()).isTrue(); // check default
		List<ConfigAttribute> config = SecurityConfig.createList("IGNORED_BY_ALL");
		try {
			mgr.decide(auth, new Object(), config);
			fail("Should have thrown AccessDeniedException");
		}
		catch (AccessDeniedException expected) {
		}
	}

	@Test
	public void testThreeAbstainVotesGrantsAccessWithoutDefault() {
		TestingAuthenticationToken auth = makeTestToken();
		UnanimousBased mgr = makeDecisionManager();
		mgr.setAllowIfAllAbstainDecisions(true);
		assertThat(mgr.isAllowIfAllAbstainDecisions()).isTrue(); // check changed
		List<ConfigAttribute> config = SecurityConfig.createList("IGNORED_BY_ALL");
		mgr.decide(auth, new Object(), config);
	}

	@Test
	public void testTwoAffirmativeVotesTwoAbstainVotesGrantsAccess() {
		TestingAuthenticationToken auth = makeTestToken();
		UnanimousBased mgr = makeDecisionManager();
		List<ConfigAttribute> config = SecurityConfig.createList(new String[] { "ROLE_1", "ROLE_2" });
		mgr.decide(auth, new Object(), config);
	}

}
