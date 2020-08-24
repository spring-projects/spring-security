/*
 * Copyright 2004 Acegi Technology Pty Limited
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
 * Tests {@link ConsensusBased}.
 *
 * @author Ben Alex
 */
public class ConsensusBasedTests {

	@Test(expected = AccessDeniedException.class)
	public void testOneAffirmativeVoteOneDenyVoteOneAbstainVoteDeniesAccessWithoutDefault() {
		TestingAuthenticationToken auth = makeTestToken();
		ConsensusBased mgr = makeDecisionManager();
		mgr.setAllowIfEqualGrantedDeniedDecisions(false);
		assertThat(!mgr.isAllowIfEqualGrantedDeniedDecisions()).isTrue(); // check changed
		List<ConfigAttribute> config = SecurityConfig.createList("ROLE_1", "DENY_FOR_SURE");
		mgr.decide(auth, new Object(), config);
	}

	@Test
	public void testOneAffirmativeVoteOneDenyVoteOneAbstainVoteGrantsAccessWithDefault() {
		TestingAuthenticationToken auth = makeTestToken();
		ConsensusBased mgr = makeDecisionManager();
		assertThat(mgr.isAllowIfEqualGrantedDeniedDecisions()).isTrue(); // check default
		List<ConfigAttribute> config = SecurityConfig.createList("ROLE_1", "DENY_FOR_SURE");
		mgr.decide(auth, new Object(), config);
	}

	@Test
	public void testOneAffirmativeVoteTwoAbstainVotesGrantsAccess() {
		TestingAuthenticationToken auth = makeTestToken();
		ConsensusBased mgr = makeDecisionManager();
		mgr.decide(auth, new Object(), SecurityConfig.createList("ROLE_2"));
	}

	@Test(expected = AccessDeniedException.class)
	public void testOneDenyVoteTwoAbstainVotesDeniesAccess() {
		TestingAuthenticationToken auth = makeTestToken();
		ConsensusBased mgr = makeDecisionManager();
		mgr.decide(auth, new Object(), SecurityConfig.createList("ROLE_WE_DO_NOT_HAVE"));
		fail("Should have thrown AccessDeniedException");
	}

	@Test(expected = AccessDeniedException.class)
	public void testThreeAbstainVotesDeniesAccessWithDefault() {
		TestingAuthenticationToken auth = makeTestToken();
		ConsensusBased mgr = makeDecisionManager();
		assertThat(!mgr.isAllowIfAllAbstainDecisions()).isTrue(); // check default
		mgr.decide(auth, new Object(), SecurityConfig.createList("IGNORED_BY_ALL"));
	}

	@Test
	public void testThreeAbstainVotesGrantsAccessWithoutDefault() {
		TestingAuthenticationToken auth = makeTestToken();
		ConsensusBased mgr = makeDecisionManager();
		mgr.setAllowIfAllAbstainDecisions(true);
		assertThat(mgr.isAllowIfAllAbstainDecisions()).isTrue(); // check changed
		mgr.decide(auth, new Object(), SecurityConfig.createList("IGNORED_BY_ALL"));
	}

	@Test
	public void testTwoAffirmativeVotesTwoAbstainVotesGrantsAccess() {
		TestingAuthenticationToken auth = makeTestToken();
		ConsensusBased mgr = makeDecisionManager();
		mgr.decide(auth, new Object(), SecurityConfig.createList("ROLE_1", "ROLE_2"));
	}

	private ConsensusBased makeDecisionManager() {
		RoleVoter roleVoter = new RoleVoter();
		DenyVoter denyForSureVoter = new DenyVoter();
		DenyAgainVoter denyAgainForSureVoter = new DenyAgainVoter();
		List<AccessDecisionVoter<? extends Object>> voters = new Vector<>();
		voters.add(roleVoter);
		voters.add(denyForSureVoter);
		voters.add(denyAgainForSureVoter);
		return new ConsensusBased(voters);
	}

	private TestingAuthenticationToken makeTestToken() {
		return new TestingAuthenticationToken("somebody", "password", "ROLE_1", "ROLE_2");
	}

}
