package org.springframework.security.ui.preauth.j2ee;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import junit.framework.TestCase;

import org.springframework.security.authoritymapping.MappableAttributesRetriever;
import org.springframework.security.authoritymapping.Attributes2GrantedAuthoritiesMapper;
import org.springframework.security.authoritymapping.SimpleMappableAttributesRetriever;
import org.springframework.security.authoritymapping.SimpleAttributes2GrantedAuthoritiesMapper;
import org.springframework.security.ui.preauth.PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails;
import org.springframework.security.GrantedAuthority;

import org.springframework.mock.web.MockHttpServletRequest;

/**
 *
 * @author TSARDD
 */
public class J2eeBasedPreAuthenticatedWebAuthenticationDetailsSourceTests extends TestCase {

    public final void testAfterPropertiesSetException() {
        J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource t = new J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource();
        try {
            t.afterPropertiesSet();
            fail("AfterPropertiesSet didn't throw expected exception");
        } catch (IllegalArgumentException expected) {
        } catch (Exception unexpected) {
            fail("AfterPropertiesSet throws unexpected exception");
        }
    }

    public final void testBuildDetailsHttpServletRequestNoMappedNoUserRoles() {
        String[] mappedRoles = new String[] {};
        String[] roles = new String[] {};
        String[] expectedRoles = new String[] {};
        testDetails(mappedRoles, roles, expectedRoles);
    }

    public final void testBuildDetailsHttpServletRequestNoMappedUnmappedUserRoles() {
        String[] mappedRoles = new String[] {};
        String[] roles = new String[] { "Role1", "Role2" };
        String[] expectedRoles = new String[] {};
        testDetails(mappedRoles, roles, expectedRoles);
    }

    public final void testBuildDetailsHttpServletRequestNoUserRoles() {
        String[] mappedRoles = new String[] { "Role1", "Role2", "Role3", "Role4" };
        String[] roles = new String[] {};
        String[] expectedRoles = new String[] {};
        testDetails(mappedRoles, roles, expectedRoles);
    }

    public final void testBuildDetailsHttpServletRequestAllUserRoles() {
        String[] mappedRoles = new String[] { "Role1", "Role2", "Role3", "Role4" };
        String[] roles = new String[] { "Role1", "Role2", "Role3", "Role4" };
        String[] expectedRoles = new String[] { "Role1", "Role2", "Role3", "Role4" };
        testDetails(mappedRoles, roles, expectedRoles);
    }

    public final void testBuildDetailsHttpServletRequestUnmappedUserRoles() {
        String[] mappedRoles = new String[] { "Role1", "Role2", "Role3", "Role4" };
        String[] roles = new String[] { "Role1", "Role2", "Role3", "Role4", "Role5" };
        String[] expectedRoles = new String[] { "Role1", "Role2", "Role3", "Role4" };
        testDetails(mappedRoles, roles, expectedRoles);
    }

    public final void testBuildDetailsHttpServletRequestPartialUserRoles() {
        String[] mappedRoles = new String[] { "Role1", "Role2", "Role3", "Role4" };
        String[] roles = new String[] { "Role2", "Role3" };
        String[] expectedRoles = new String[] { "Role2", "Role3" };
        testDetails(mappedRoles, roles, expectedRoles);
    }

    public final void testBuildDetailsHttpServletRequestPartialAndUnmappedUserRoles() {
        String[] mappedRoles = new String[] { "Role1", "Role2", "Role3", "Role4" };
        String[] roles = new String[] { "Role2", "Role3", "Role5" };
        String[] expectedRoles = new String[] { "Role2", "Role3" };
        testDetails(mappedRoles, roles, expectedRoles);
    }

    private void testDetails(String[] mappedRoles, String[] userRoles, String[] expectedRoles) {
        J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource src = getJ2eeBasedPreAuthenticatedWebAuthenticationDetailsSource(mappedRoles);
        Object o = src.buildDetails(getRequest("testUser", userRoles));
        assertNotNull(o);
        assertTrue("Returned object not of type PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails, actual type: " + o.getClass(),
                o instanceof PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails);
        PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails details = (PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails) o;
        List<GrantedAuthority> gas = details.getGrantedAuthorities();
        assertNotNull("Granted authorities should not be null", gas);
        assertEquals(expectedRoles.length, gas.size());

        Collection expectedRolesColl = Arrays.asList(expectedRoles);
        Collection gasRolesSet = new HashSet();
        for (int i = 0; i < gas.size(); i++) {
            gasRolesSet.add(gas.get(i).getAuthority());
        }
        assertTrue("Granted Authorities do not match expected roles", expectedRolesColl.containsAll(gasRolesSet)
                && gasRolesSet.containsAll(expectedRolesColl));
    }

    private final J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource getJ2eeBasedPreAuthenticatedWebAuthenticationDetailsSource(
            String[] mappedRoles) {
        J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource result = new J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource();
        result.setMappableRolesRetriever(getMappableRolesRetriever(mappedRoles));
        result.setUserRoles2GrantedAuthoritiesMapper(getJ2eeUserRoles2GrantedAuthoritiesMapper());
        result.setClazz(PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails.class);

        try {
            result.afterPropertiesSet();
        } catch (Exception expected) {
            fail("AfterPropertiesSet throws unexpected exception");
        }
        return result;
    }

    private MappableAttributesRetriever getMappableRolesRetriever(String[] mappedRoles) {
        SimpleMappableAttributesRetriever result = new SimpleMappableAttributesRetriever();
        result.setMappableAttributes(mappedRoles);
        return result;
    }

    private Attributes2GrantedAuthoritiesMapper getJ2eeUserRoles2GrantedAuthoritiesMapper() {
        SimpleAttributes2GrantedAuthoritiesMapper result = new SimpleAttributes2GrantedAuthoritiesMapper();
        result.setAddPrefixIfAlreadyExisting(false);
        result.setConvertAttributeToLowerCase(false);
        result.setConvertAttributeToUpperCase(false);
        result.setAttributePrefix("");
        return result;
    }

    private final HttpServletRequest getRequest(final String userName,final String[] aRoles)
    {
        MockHttpServletRequest req = new MockHttpServletRequest() {
            private Set roles = new HashSet(Arrays.asList(aRoles));
            public boolean isUserInRole(String arg0) {
                return roles.contains(arg0);
            }
        };
        req.setRemoteUser(userName);
        return req;
    }
}
