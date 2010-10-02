package org.springframework.security.authentication;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 *
 * @author Luke Taylor
 */
@SuppressWarnings({"deprecation"})
public class AuthenticationDetailsSourceImplTests {

    @Test
    public void buildDetailsReturnsExpectedAuthenticationDetails() {
        AuthenticationDetailsSourceImpl ads = new AuthenticationDetailsSourceImpl();
        AuthenticationDetails details = (AuthenticationDetails) ads.buildDetails("the context");
        assertEquals("the context", details.getContext());
        assertEquals(new AuthenticationDetails("the context"), details);
        ads.setClazz(AuthenticationDetails.class);
        details = (AuthenticationDetails) ads.buildDetails("another context");
        assertEquals("another context", details.getContext());
    }

    @Test(expected=IllegalStateException.class)
    public void nonMatchingConstructorIsRejected() {
        AuthenticationDetailsSourceImpl ads = new AuthenticationDetailsSourceImpl();
        ads.setClazz(String.class);
        ads.buildDetails(new Object());
    }

    @Test(expected=IllegalStateException.class)
    public void constructorTakingMultipleArgumentsIsRejected() {
        AuthenticationDetailsSourceImpl ads = new AuthenticationDetailsSourceImpl();
        ads.setClazz(TestingAuthenticationToken.class);
        ads.buildDetails(null);
    }

    @Test
    public void authenticationDetailsEqualsBehavesAsExpected() {
        AuthenticationDetails details = new AuthenticationDetails("the context");
        assertFalse((new AuthenticationDetails("different context")).equals(details));
        assertFalse((new AuthenticationDetails(null)).equals(details));
        assertFalse(details.equals(new AuthenticationDetails(null)));
        assertFalse(details.equals("a string"));
        // Just check toString() functions OK
        details.toString();
        (new AuthenticationDetails(null)).toString();
    }

}
