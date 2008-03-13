package org.springframework.security.ui.preauth;

import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.GrantedAuthority;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import junit.framework.TestCase;

import org.springframework.mock.web.MockHttpServletRequest;

/**
 * @author TSARDD
 */
public class PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetailsTests extends TestCase {

    public final void testToString() {
		PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails details = new PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails(
				getRequest("testUser", new String[] {}));
		GrantedAuthority[] gas = new GrantedAuthority[] { new GrantedAuthorityImpl("Role1"), new GrantedAuthorityImpl("Role2") };
		details.setGrantedAuthorities(gas);
		String toString = details.toString();
		assertTrue("toString should contain Role1", toString.contains("Role1"));
		assertTrue("toString should contain Role2", toString.contains("Role2"));
	}

	public final void testGetSetPreAuthenticatedGrantedAuthorities() {
		PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails details = new PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails(
				getRequest("testUser", new String[] {}));
		GrantedAuthority[] gas = new GrantedAuthority[] { new GrantedAuthorityImpl("Role1"), new GrantedAuthorityImpl("Role2") };
		Collection expectedGas = Arrays.asList(gas);

		details.setGrantedAuthorities(gas);
		Collection returnedGas = Arrays.asList(details.getGrantedAuthorities());
		assertTrue("Collections do not contain same elements; expected: " + expectedGas + ", returned: " + returnedGas, 
		        expectedGas.containsAll(returnedGas) && returnedGas.containsAll(expectedGas));
	}

	public final void testGetWithoutSetPreAuthenticatedGrantedAuthorities() {
		PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails details = new PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails(
				getRequest("testUser", new String[] {}));
		try {
			GrantedAuthority[] gas = details.getGrantedAuthorities();
			fail("Expected exception didn't occur");
		} catch (IllegalArgumentException expected) {
		} catch (Exception unexpected) {
			fail("Unexpected exception: " + unexpected.toString());
		}
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
