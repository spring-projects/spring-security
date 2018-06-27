/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.access.vote;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.Test;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 *
 * @author Marco Schaub
 */
public class PermissionVoterTests {

	@Test
	public void nullAuthenticationDenies() {
		PermissionVoter voter = new PermissionVoter();
		Authentication userAB = null;
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("test"))).isEqualTo(AccessDecisionVoter.ACCESS_DENIED);
	}

	@Test
	public void matchingSinglePathPermission() {
		PermissionVoter voter = new PermissionVoter();
		Authentication userAB = new TestingAuthenticationToken("user", "pass", "test", "B");
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("test"))).isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
	}

	@Test
	public void nonMatchingSinglePathPermission() {
		PermissionVoter voter = new PermissionVoter();
		Authentication userAB = new TestingAuthenticationToken("user", "pass", "A", "B");
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("test"))).isEqualTo(AccessDecisionVoter.ACCESS_DENIED);
	}

	@Test
	public void matchingMultiPathPermission() {
		PermissionVoter voter = new PermissionVoter();
		Authentication userAB = new TestingAuthenticationToken("user", "pass", "test.module1.sub1", "B");
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("test.module1.sub1"))).isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
	}

	@Test
	public void nonMatchingMultiPathPermission() {
		PermissionVoter voter = new PermissionVoter();
		Authentication userAB = new TestingAuthenticationToken("user", "pass", "test.module1.sub1", "B");
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("test.module1.sub2"))).isEqualTo(AccessDecisionVoter.ACCESS_DENIED);
	}

	@Test
	public void matchingPathPermissionSingleLevelWildcard() {
		PermissionVoter voter = new PermissionVoter();
		Authentication userAB = new TestingAuthenticationToken("user", "pass", "test.*.sub1", "B");
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("test.modul1.sub1"))).isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("test.modul2.sub1"))).isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
	}

	@Test
	public void nonMatchingPathPermissionSingleLevelWildcard() {
		PermissionVoter voter = new PermissionVoter();
		Authentication userAB = new TestingAuthenticationToken("user", "pass", "test.*.sub1", "B");
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("test.modul1.sub2"))).isEqualTo(AccessDecisionVoter.ACCESS_DENIED);
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("test.modul2.sub2"))).isEqualTo(AccessDecisionVoter.ACCESS_DENIED);
	}

	@Test
	public void matchingPathPermissionMultiLevelWildcard() {
		PermissionVoter voter = new PermissionVoter();
		Authentication userAB = new TestingAuthenticationToken("user", "pass", "test.**", "B");
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("test.modul1.sub1.config1"))).isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("test.modul2.sub2.config1"))).isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
	}

	@Test
	public void matchingPermissionToken() {
		PermissionVoter voter = new PermissionVoter();
		Authentication userAB = new TestingAuthenticationToken("user", "pass", "test:read,write", "B");
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("test:read"))).isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("test:write"))).isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
	}

	@Test
	public void nonMatchingPermissionToken() {
		PermissionVoter voter = new PermissionVoter();
		Authentication userAB = new TestingAuthenticationToken("user", "pass", "test:read,write", "B");
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("test:delete"))).isEqualTo(AccessDecisionVoter.ACCESS_DENIED);
	}

	@Test
	public void matchingImpliedWildcardPermissionToken() {
		PermissionVoter voter = new PermissionVoter();
		Authentication userAB = new TestingAuthenticationToken("user", "pass", "test", "B");
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("test:read"))).isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("test:write"))).isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
	}

	@Test
	public void matchingWildcardPermissionToken() {
		PermissionVoter voter = new PermissionVoter();
		Authentication userAB = new TestingAuthenticationToken("user", "pass", "test:*", "B");
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("test:read"))).isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("test:write"))).isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
	}

	@Test
	public void matchingInstanceObjectToken() {
		PermissionVoter voter = new PermissionVoter();
		Authentication userAB = new TestingAuthenticationToken("user", "pass", "test:*:500", "B");
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("test:read:500"))).isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("test:write:500"))).isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
	}

	@Test
	public void matchingImpliedWildcardInstanceObjectToken() {
		PermissionVoter voter = new PermissionVoter();
		Authentication userAB = new TestingAuthenticationToken("user", "pass", "test:*", "B");
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("test:read:500"))).isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("test:write:500"))).isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
	}

	@Test
	public void nonMatchingInstanceObjectToken() {
		PermissionVoter voter = new PermissionVoter();
		Authentication userAB = new TestingAuthenticationToken("user", "pass", "test:*:500", "B");
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("test:read:501"))).isEqualTo(AccessDecisionVoter.ACCESS_DENIED);
	}

	@Test
	public void matchingCombinations() {
		PermissionVoter voter = new PermissionVoter();
		Authentication userAB = new TestingAuthenticationToken("user", "pass", "test.*.sub1.**:write,read:500", "B");
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("test.module1.sub1:read"))).isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("test.module2.sub1.config1:write:500"))).isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
	}

}
