package org.springframework.security.providers.openid;

import junit.framework.TestCase;

/**
 * DOCUMENT ME!
 *
 * @author Ray Krueger
 */
public class OpenIdAuthenticationTokenTests extends TestCase {

    public void test() throws Exception {
        OpenIDAuthenticationToken token = newToken();
        assertEquals(token, newToken());
    }

    private OpenIDAuthenticationToken newToken() {
        return new OpenIDAuthenticationToken(
                OpenIDAuthenticationStatus.SUCCESS,
                "http://raykrueger.blogspot.com/",
                "what is this for anyway?");
    }


}
