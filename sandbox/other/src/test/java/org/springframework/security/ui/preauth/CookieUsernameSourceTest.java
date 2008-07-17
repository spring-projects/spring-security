/**
 * 
 */
package org.springframework.security.ui.preauth;

import javax.servlet.http.Cookie;

import junit.framework.TestCase;

import org.springframework.mock.web.MockHttpServletRequest;

/**
 * @author tydykov
 * 
 */
public class CookieUsernameSourceTest extends TestCase {

    CookieUsernameSource usernameSource;

    /*
     * (non-Javadoc)
     * 
     * @see junit.framework.TestCase#setUp()
     */
    protected void setUp() throws Exception {
        usernameSource = new CookieUsernameSource();
    }

    /*
     * (non-Javadoc)
     * 
     * @see junit.framework.TestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        usernameSource = null;
    }

    public final void testObtainUsernameSupplied() {
        String key1 = "key1";
        String value1 = "value1";

        MockHttpServletRequest request = new MockHttpServletRequest();
        {
            Cookie[] cookies = new Cookie[] { new Cookie(key1, value1) };
            request.setCookies(cookies);
        }

        usernameSource.setUsernameKey(key1);
        String username = usernameSource.obtainUsername(request);

        assertEquals(value1, username);
    }

    public final void testObtainUsernameNotSupplied() {
        String key1 = "key1";

        MockHttpServletRequest request = new MockHttpServletRequest();

        usernameSource.setUsernameKey(key1);
        String username = usernameSource.obtainUsername(request);

        assertEquals(null, username);
    }
}
