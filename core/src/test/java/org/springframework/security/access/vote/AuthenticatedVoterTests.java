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

import org.junit.Test;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Tests {@link AuthenticatedVoter}.
 *
 * @author Ben Alex
 */
public class AuthenticatedVoterTests {

	private Authentication createAnonymous() {
		return new AnonymousAuthenticationToken("ignored", "ignored", AuthorityUtils.createAuthorityList("ignored"));
	}

	private Authentication createFullyAuthenticated() {
		return new UsernamePasswordAuthenticationToken("ignored", "ignored",
				AuthorityUtils.createAuthorityList("ignored"));
	}

	private Authentication createRememberMe() {
		return new RememberMeAuthenticationToken("ignored", "ignored", AuthorityUtils.createAuthorityList("ignored"));
	}

	@Test
	public void testAnonymousWorks() {
		AuthenticatedVoter voter = new AuthenticatedVoter();
		List<ConfigAttribute> def = SecurityConfig.createList(AuthenticatedVoter.IS_AUTHENTICATED_ANONYMOUSLY);
		assertThat(AccessDecisionVoter.ACCESS_GRANTED).isEqualTo(voter.vote(createAnonymous(), null, def));
		assertThat(AccessDecisionVoter.ACCESS_GRANTED).isEqualTo(voter.vote(createRememberMe(), null, def));
		assertThat(AccessDecisionVoter.ACCESS_GRANTED).isEqualTo(voter.vote(createFullyAuthenticated(), null, def));
	}

	@Test
	public void testFullyWorks() {
		AuthenticatedVoter voter = new AuthenticatedVoter();
		List<ConfigAttribute> def = SecurityConfig.createList(AuthenticatedVoter.IS_AUTHENTICATED_FULLY);
		assertThat(AccessDecisionVoter.ACCESS_DENIED).isEqualTo(voter.vote(createAnonymous(), null, def));
		assertThat(AccessDecisionVoter.ACCESS_DENIED).isEqualTo(voter.vote(createRememberMe(), null, def));
		assertThat(AccessDecisionVoter.ACCESS_GRANTED).isEqualTo(voter.vote(createFullyAuthenticated(), null, def));
	}

	@Test
	public void testRememberMeWorks() {
		AuthenticatedVoter voter = new AuthenticatedVoter();
		List<ConfigAttribute> def = SecurityConfig.createList(AuthenticatedVoter.IS_AUTHENTICATED_REMEMBERED);
		assertThat(AccessDecisionVoter.ACCESS_DENIED).isEqualTo(voter.vote(createAnonymous(), null, def));
		assertThat(AccessDecisionVoter.ACCESS_GRANTED).isEqualTo(voter.vote(createRememberMe(), null, def));
		assertThat(AccessDecisionVoter.ACCESS_GRANTED).isEqualTo(voter.vote(createFullyAuthenticated(), null, def));
	}

	@Test
	public void testSetterRejectsNull() {
		AuthenticatedVoter voter = new AuthenticatedVoter();

		try {
			voter.setAuthenticationTrustResolver(null);
			fail("Expected IAE");
		}
		catch (IllegalArgumentException expected) {

		}
	}

	@Test
	public void testSupports() {
		AuthenticatedVoter voter = new AuthenticatedVoter();
		assertThat(voter.supports(String.class)).isTrue();
		assertThat(voter.supports(new SecurityConfig(AuthenticatedVoter.IS_AUTHENTICATED_ANONYMOUSLY))).isTrue();
		assertThat(voter.supports(new SecurityConfig(AuthenticatedVoter.IS_AUTHENTICATED_FULLY))).isTrue();
		assertThat(voter.supports(new SecurityConfig(AuthenticatedVoter.IS_AUTHENTICATED_REMEMBERED))).isTrue();
		assertThat(voter.supports(new SecurityConfig("FOO"))).isFalse();
	}

}
