package org.springframework.security.access.vote;

import static org.assertj.core.api.Assertions.*;

import org.junit.Test;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 *
 * @author Luke Taylor
 */
public class RoleVoterTests {
	@Test
	public void oneMatchingAttributeGrantsAccess() {
		RoleVoter voter = new RoleVoter();
		voter.setRolePrefix("");
		Authentication userAB = new TestingAuthenticationToken("user", "pass", "A", "B");
		// Vote on attribute list that has two attributes A and C (i.e. only one matching)
		assertThat(voter.vote(userAB, this, SecurityConfig.createList("A", "C"))).isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
	}

	// SEC-3128
	@Test
	public void nullAuthenticationDenies() {
		RoleVoter voter = new RoleVoter();
		voter.setRolePrefix("");
		Authentication notAuthenitcated = null;
		assertThat(voter.vote(notAuthenitcated, this, SecurityConfig.createList("A"))).isEqualTo(AccessDecisionVoter.ACCESS_DENIED);
	}
}
