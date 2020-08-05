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
package org.springframework.security.access.annotation;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.authentication.TestingAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Luke Taylor
 */
public class Jsr250VoterTests {

	// SEC-1443
	@Test
	public void supportsMultipleRolesCorrectly() {
		List<ConfigAttribute> attrs = new ArrayList<>();
		Jsr250Voter voter = new Jsr250Voter();

		attrs.add(new Jsr250SecurityConfig("A"));
		attrs.add(new Jsr250SecurityConfig("B"));
		attrs.add(new Jsr250SecurityConfig("C"));

		assertThat(voter.vote(new TestingAuthenticationToken("user", "pwd", "A"), new Object(), attrs))
				.isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
		assertThat(voter.vote(new TestingAuthenticationToken("user", "pwd", "B"), new Object(), attrs))
				.isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
		assertThat(voter.vote(new TestingAuthenticationToken("user", "pwd", "C"), new Object(), attrs))
				.isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);

		assertThat(voter.vote(new TestingAuthenticationToken("user", "pwd", "NONE"), new Object(), attrs))
				.isEqualTo(AccessDecisionVoter.ACCESS_DENIED);

		assertThat(voter.vote(new TestingAuthenticationToken("user", "pwd", "A"), new Object(),
				SecurityConfig.createList("A", "B", "C"))).isEqualTo(AccessDecisionVoter.ACCESS_ABSTAIN);
	}

}
