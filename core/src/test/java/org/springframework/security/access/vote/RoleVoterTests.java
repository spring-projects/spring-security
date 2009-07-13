package org.springframework.security.access.vote;

import static org.junit.Assert.*;

import org.junit.Test;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class RoleVoterTests {

    // Vote on attribute list that has two attributes A and C (i.e. one matching)
    @Test
    public void oneMatchingAttributeGrantsAccess() {
        RoleVoter voter = new RoleVoter();
        voter.setRolePrefix("");
        Authentication userAB = new TestingAuthenticationToken("user","pass", "A", "B");
        assertEquals(AccessDecisionVoter.ACCESS_GRANTED, voter.vote(userAB, this, SecurityConfig.createList("A","C")));
    }
}
