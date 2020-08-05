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

import java.util.Collection;
import java.util.List;
import java.util.Vector;

import org.junit.Test;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Tests {@link AbstractAccessDecisionManager}.
 *
 * @author Ben Alex
 */
@SuppressWarnings("unchecked")
public class AbstractAccessDecisionManagerTests {

	@Test
	public void testAllowIfAccessDecisionManagerDefaults() {
		List list = new Vector();
		DenyAgainVoter denyVoter = new DenyAgainVoter();
		list.add(denyVoter);
		MockDecisionManagerImpl mock = new MockDecisionManagerImpl(list);
		assertThat(!mock.isAllowIfAllAbstainDecisions()).isTrue(); // default
		mock.setAllowIfAllAbstainDecisions(true);
		assertThat(mock.isAllowIfAllAbstainDecisions()).isTrue(); // changed
	}

	@Test
	public void testDelegatesSupportsClassRequests() {
		List list = new Vector();
		list.add(new DenyVoter());
		list.add(new MockStringOnlyVoter());

		MockDecisionManagerImpl mock = new MockDecisionManagerImpl(list);

		assertThat(mock.supports(String.class)).isTrue();
		assertThat(!mock.supports(Integer.class)).isTrue();
	}

	@Test
	public void testDelegatesSupportsRequests() {
		List list = new Vector();
		DenyVoter voter = new DenyVoter();
		DenyAgainVoter denyVoter = new DenyAgainVoter();
		list.add(voter);
		list.add(denyVoter);

		MockDecisionManagerImpl mock = new MockDecisionManagerImpl(list);

		ConfigAttribute attr = new SecurityConfig("DENY_AGAIN_FOR_SURE");
		assertThat(mock.supports(attr)).isTrue();

		ConfigAttribute badAttr = new SecurityConfig("WE_DONT_SUPPORT_THIS");
		assertThat(!mock.supports(badAttr)).isTrue();
	}

	@Test
	public void testProperlyStoresListOfVoters() {
		List list = new Vector();
		DenyVoter voter = new DenyVoter();
		DenyAgainVoter denyVoter = new DenyAgainVoter();
		list.add(voter);
		list.add(denyVoter);
		MockDecisionManagerImpl mock = new MockDecisionManagerImpl(list);
		assertThat(mock.getDecisionVoters()).hasSize(list.size());
	}

	@Test
	public void testRejectsEmptyList() {
		List list = new Vector();

		try {
			new MockDecisionManagerImpl(list);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {

		}
	}

	@Test
	public void testRejectsNullVotersList() {
		try {
			new MockDecisionManagerImpl(null);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {

		}
	}

	@Test
	public void testRoleVoterAlwaysReturnsTrueToSupports() {
		RoleVoter rv = new RoleVoter();
		assertThat(rv.supports(String.class)).isTrue();
	}

	@Test
	public void testWillNotStartIfDecisionVotersNotSet() {
		try {
			new MockDecisionManagerImpl(null);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {

		}
	}

	private class MockDecisionManagerImpl extends AbstractAccessDecisionManager {

		protected MockDecisionManagerImpl(List<AccessDecisionVoter<? extends Object>> decisionVoters) {
			super(decisionVoters);
		}

		public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes) {
		}

	}

	private class MockStringOnlyVoter implements AccessDecisionVoter<Object> {

		public boolean supports(Class<?> clazz) {
			return String.class.isAssignableFrom(clazz);
		}

		public boolean supports(ConfigAttribute attribute) {
			throw new UnsupportedOperationException("mock method not implemented");
		}

		public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
			throw new UnsupportedOperationException("mock method not implemented");
		}

	}

}
