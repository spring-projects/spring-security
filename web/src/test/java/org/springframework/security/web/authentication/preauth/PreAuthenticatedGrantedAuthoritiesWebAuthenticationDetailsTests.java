package org.springframework.security.web.authentication.preauth;

import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * @author TSARDD
 */
public class PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetailsTests {
    List<GrantedAuthority> gas = AuthorityUtils.createAuthorityList("Role1", "Role2");

    @Test
    public void testToString() {
        PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails details = new PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails(
                getRequest("testUser", new String[] {}), gas);
        String toString = details.toString();
        assertTrue("toString should contain Role1", toString.contains("Role1"));
        assertTrue("toString should contain Role2", toString.contains("Role2"));
    }

    @Test
    public void testGetSetPreAuthenticatedGrantedAuthorities() {
        PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails details = new PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails(
                getRequest("testUser", new String[] {}), gas);
        List<GrantedAuthority> returnedGas = details.getGrantedAuthorities();
        assertTrue("Collections do not contain same elements; expected: " + gas + ", returned: " + returnedGas,
                gas.containsAll(returnedGas) && returnedGas.containsAll(gas));
    }

    private HttpServletRequest getRequest(final String userName,final String[] aRoles) {
        MockHttpServletRequest req = new MockHttpServletRequest() {
            private Set<String> roles = new HashSet<String>(Arrays.asList(aRoles));
            public boolean isUserInRole(String arg0) {
                return roles.contains(arg0);
            }
        };
        req.setRemoteUser(userName);
        return req;
    }

}
