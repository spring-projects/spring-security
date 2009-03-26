package org.springframework.security.web.authentication.preauth.j2ee;

import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import junit.framework.TestCase;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.authentication.preauth.j2ee.J2eePreAuthenticatedProcessingFilter;

/**
 *
 * @author TSARDD
 * @since 18-okt-2007
 */
public class J2eePreAuthenticatedProcessingFilterTests extends TestCase {

    public final void testGetPreAuthenticatedPrincipal() {
        String user = "testUser";
        assertEquals(user, new J2eePreAuthenticatedProcessingFilter().getPreAuthenticatedPrincipal(
            getRequest(user,new String[] {})));
    }

    public final void testGetPreAuthenticatedCredentials() {
        assertEquals("N/A", new J2eePreAuthenticatedProcessingFilter().getPreAuthenticatedCredentials(
            getRequest("testUser", new String[] {})));
    }

    private final HttpServletRequest getRequest(final String aUserName,final String[] aRoles)
    {
        MockHttpServletRequest req = new MockHttpServletRequest() {
            private Set<String> roles = new HashSet<String>(Arrays.asList(aRoles));
            public boolean isUserInRole(String arg0) {
                return roles.contains(arg0);
            }
        };
        req.setRemoteUser(aUserName);
        req.setUserPrincipal(new Principal() {
            public String getName() {
                return aUserName;
            }
        });
        return req;
    }

}
