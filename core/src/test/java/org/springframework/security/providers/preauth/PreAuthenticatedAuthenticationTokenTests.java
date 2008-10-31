package org.springframework.security.providers.preauth;

import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.GrantedAuthority;

import java.util.Arrays;
import java.util.Collection;

import junit.framework.TestCase;

/**
 *
 * @author TSARDD
 * @since 18-okt-2007
 */
public class PreAuthenticatedAuthenticationTokenTests extends TestCase {

    public void testPreAuthenticatedAuthenticationTokenRequestWithDetails() {
        Object principal = "dummyUser";
        Object credentials = "dummyCredentials";
        Object details = "dummyDetails";
        PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(principal, credentials);
        token.setDetails(details);
        assertEquals(principal, token.getPrincipal());
        assertEquals(credentials, token.getCredentials());
        assertEquals(details, token.getDetails());
        assertNull(token.getAuthorities());
    }

    public void testPreAuthenticatedAuthenticationTokenRequestWithoutDetails() {
        Object principal = "dummyUser";
        Object credentials = "dummyCredentials";
        PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(principal, credentials);
        assertEquals(principal, token.getPrincipal());
        assertEquals(credentials, token.getCredentials());
        assertNull(token.getDetails());
        assertNull(token.getAuthorities());
    }

    public void testPreAuthenticatedAuthenticationTokenResponse() {
        Object principal = "dummyUser";
        Object credentials = "dummyCredentials";
        GrantedAuthority[] gas = new GrantedAuthority[] { new GrantedAuthorityImpl("Role1") };
        PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(principal, credentials, gas);
        assertEquals(principal, token.getPrincipal());
        assertEquals(credentials, token.getCredentials());
        assertNull(token.getDetails());
        assertNotNull(token.getAuthorities());
        Collection expectedColl = Arrays.asList(gas);
        Collection resultColl = token.getAuthorities();
        assertTrue("GrantedAuthority collections do not match; result: " + resultColl + ", expected: " + expectedColl,
                expectedColl.containsAll(resultColl) && resultColl.containsAll(expectedColl));

    }

}
