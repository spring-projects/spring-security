package org.springframework.security.access.annotation;

import static org.junit.Assert.*;

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

        assertEquals(AccessDecisionVoter.ACCESS_GRANTED,
                voter.vote(new TestingAuthenticationToken("user", "pwd", "A"), new Object(), attrs));
        assertEquals(AccessDecisionVoter.ACCESS_GRANTED,
                voter.vote(new TestingAuthenticationToken("user", "pwd", "B"), new Object(), attrs));
        assertEquals(AccessDecisionVoter.ACCESS_GRANTED,
                voter.vote(new TestingAuthenticationToken("user", "pwd", "C"), new Object(), attrs));

        assertEquals(AccessDecisionVoter.ACCESS_DENIED,
                voter.vote(new TestingAuthenticationToken("user", "pwd", "NONE"), new Object(), attrs));

        assertEquals(AccessDecisionVoter.ACCESS_ABSTAIN,
                voter.vote(new TestingAuthenticationToken("user", "pwd", "A"), new Object(),
                        SecurityConfig.createList("A","B","C")));
    }
}
