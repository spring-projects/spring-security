package org.springframework.security.access.annotation;

import static org.assertj.core.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.authentication.TestingAuthenticationToken;

/**
 *
 * @author Luke Taylor
 */
public class Jsr250VoterTests {

	// SEC-1443
	@Test
	public void supportsMultipleRolesCorrectly() throws Exception {
		List<ConfigAttribute> attrs = new ArrayList<ConfigAttribute>();
		Jsr250Voter voter = new Jsr250Voter();

		attrs.add(new Jsr250SecurityConfig("A"));
		attrs.add(new Jsr250SecurityConfig("B"));
		attrs.add(new Jsr250SecurityConfig("C"));

		assertThat(voter.vote(
				new TestingAuthenticationToken("user", "pwd", "A"), new Object(), attrs)).isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
		assertThat(voter.vote(
				new TestingAuthenticationToken("user", "pwd", "B"), new Object(), attrs)).isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
		assertThat(voter.vote(
				new TestingAuthenticationToken("user", "pwd", "C"), new Object(), attrs)).isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);

		assertThat(voter.vote(
				new TestingAuthenticationToken("user", "pwd", "NONE"), new Object(),
				attrs)).isEqualTo(AccessDecisionVoter.ACCESS_DENIED);

		assertThat(voter.vote(
				new TestingAuthenticationToken("user", "pwd", "A"), new Object(),
				SecurityConfig.createList("A", "B", "C"))).isEqualTo(AccessDecisionVoter.ACCESS_ABSTAIN);
	}
}
