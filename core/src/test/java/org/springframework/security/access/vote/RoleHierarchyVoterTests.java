package org.springframework.security.access.vote;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.authentication.TestingAuthenticationToken;

public class RoleHierarchyVoterTests {

    @Test
    public void hierarchicalRoleIsIncludedInDecision() {
        RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();
        roleHierarchyImpl.setHierarchy("ROLE_A > ROLE_B");

        // User has role A, role B is required
        TestingAuthenticationToken auth = new TestingAuthenticationToken("user", "password", "ROLE_A");
        RoleHierarchyVoter voter = new RoleHierarchyVoter(roleHierarchyImpl);

        assertEquals(RoleHierarchyVoter.ACCESS_GRANTED, voter.vote(auth, new Object(), SecurityConfig.createList("ROLE_B")));
    }
}
