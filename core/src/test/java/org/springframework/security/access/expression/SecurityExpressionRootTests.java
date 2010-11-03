package org.springframework.security.access.expression;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collection;

import org.junit.Test;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class SecurityExpressionRootTests {
    private final Authentication JOE = new TestingAuthenticationToken("joe", "pass", "A", "B");

    @Test
    public void denyAllIsFalsePermitAllTrue() throws Exception {
        SecurityExpressionRoot root = new SecurityExpressionRoot(JOE) {};
        assertFalse(root.denyAll());
        assertFalse(root.denyAll);
        assertTrue(root.permitAll());
        assertTrue(root.permitAll);
    }

    @Test
    public void rememberMeIsCorrectlyDetected() throws Exception {
        SecurityExpressionRoot root = new SecurityExpressionRoot(JOE) {};
        AuthenticationTrustResolver atr = mock(AuthenticationTrustResolver.class);
        root.setTrustResolver(atr);
        when(atr.isRememberMe(JOE)).thenReturn(true);
        assertTrue(root.isRememberMe());
        assertFalse(root.isFullyAuthenticated());
    }

    @Test
    public void roleHierarchySupportIsCorrectlyUsedInEvaluatingRoles() throws Exception {
        SecurityExpressionRoot root = new SecurityExpressionRoot(JOE) {};

        root.setRoleHierarchy(new RoleHierarchy() {
            public Collection<GrantedAuthority> getReachableGrantedAuthorities(Collection<? extends GrantedAuthority> authorities) {
                return AuthorityUtils.createAuthorityList("C");
            }
        });

        assertTrue(root.hasRole("C"));
        assertTrue(root.hasAuthority("C"));
        assertFalse(root.hasRole("A"));
        assertFalse(root.hasRole("B"));
        assertTrue(root.hasAnyRole("C", "A", "B"));
        assertTrue(root.hasAnyAuthority("C", "A", "B"));
        assertFalse(root.hasAnyRole("A", "B"));
    }
}
