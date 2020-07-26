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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests {@link AffirmativeBased}.
 *
 * @author Ben Alex
 */
public class AffirmativeBasedTests {

	private final List<ConfigAttribute> attrs = new ArrayList<>();

	private final Authentication user = new TestingAuthenticationToken("somebody", "password", "ROLE_1", "ROLE_2");

	private AffirmativeBased mgr;

	private AccessDecisionVoter grant;

	private AccessDecisionVoter abstain;

	private AccessDecisionVoter deny;

	@Before
	@SuppressWarnings("unchecked")
	public void setup() {

		this.grant = mock(AccessDecisionVoter.class);
		this.abstain = mock(AccessDecisionVoter.class);
		this.deny = mock(AccessDecisionVoter.class);

		when(this.grant.vote(any(Authentication.class), any(Object.class), any(List.class)))
				.thenReturn(AccessDecisionVoter.ACCESS_GRANTED);
		when(this.abstain.vote(any(Authentication.class), any(Object.class), any(List.class)))
				.thenReturn(AccessDecisionVoter.ACCESS_ABSTAIN);
		when(this.deny.vote(any(Authentication.class), any(Object.class), any(List.class)))
				.thenReturn(AccessDecisionVoter.ACCESS_DENIED);
	}

	@Test
	public void oneAffirmativeVoteOneDenyVoteOneAbstainVoteGrantsAccess() throws Exception {

		this.mgr = new AffirmativeBased(
				Arrays.<AccessDecisionVoter<? extends Object>>asList(this.grant, this.deny, this.abstain));
		this.mgr.afterPropertiesSet();
		this.mgr.decide(this.user, new Object(), this.attrs);
	}

	@Test
	public void oneDenyVoteOneAbstainVoteOneAffirmativeVoteGrantsAccess() {
		this.mgr = new AffirmativeBased(
				Arrays.<AccessDecisionVoter<? extends Object>>asList(this.deny, this.abstain, this.grant));
		this.mgr.decide(this.user, new Object(), this.attrs);
	}

	@Test
	public void oneAffirmativeVoteTwoAbstainVotesGrantsAccess() {
		this.mgr = new AffirmativeBased(
				Arrays.<AccessDecisionVoter<? extends Object>>asList(this.grant, this.abstain, this.abstain));
		this.mgr.decide(this.user, new Object(), this.attrs);
	}

	@Test(expected = AccessDeniedException.class)
	public void oneDenyVoteTwoAbstainVotesDeniesAccess() {
		this.mgr = new AffirmativeBased(
				Arrays.<AccessDecisionVoter<? extends Object>>asList(this.deny, this.abstain, this.abstain));
		this.mgr.decide(this.user, new Object(), this.attrs);
	}

	@Test(expected = AccessDeniedException.class)
	public void onlyAbstainVotesDeniesAccessWithDefault() {
		this.mgr = new AffirmativeBased(
				Arrays.<AccessDecisionVoter<? extends Object>>asList(this.abstain, this.abstain, this.abstain));
		assertThat(!this.mgr.isAllowIfAllAbstainDecisions()).isTrue(); // check default

		this.mgr.decide(this.user, new Object(), this.attrs);
	}

	@Test
	public void testThreeAbstainVotesGrantsAccessIfAllowIfAllAbstainDecisionsIsSet() {
		this.mgr = new AffirmativeBased(
				Arrays.<AccessDecisionVoter<? extends Object>>asList(this.abstain, this.abstain, this.abstain));
		this.mgr.setAllowIfAllAbstainDecisions(true);
		assertThat(this.mgr.isAllowIfAllAbstainDecisions()).isTrue(); // check changed

		this.mgr.decide(this.user, new Object(), this.attrs);
	}

}
