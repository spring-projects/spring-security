package org.springframework.security.access.expression;

import static org.junit.Assert.*;

import java.util.Collection;

import org.junit.Test;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public class SecurityExpressionRootTests {

    @Test
    public void roleHierarchySupportIsCorrectlyUsedInEvaluatingRoles() throws Exception {
        SecurityExpressionRoot root =
            new SecurityExpressionRoot(new TestingAuthenticationToken("joe", "pass", "A", "B")) {};

        root.setRoleHierarchy(new RoleHierarchy() {
            public Collection<GrantedAuthority> getReachableGrantedAuthorities(Collection<GrantedAuthority> authorities) {
                return AuthorityUtils.createAuthorityList("C");
            }
        });

        assertTrue(root.hasRole("C"));
        assertFalse(root.hasRole("A"));
        assertFalse(root.hasRole("B"));
        assertTrue(root.hasAnyRole("C", "A", "B"));
        assertFalse(root.hasAnyRole("A", "B"));
    }
}
