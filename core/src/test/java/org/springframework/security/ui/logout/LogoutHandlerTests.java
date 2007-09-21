package org.springframework.security.ui.logout;

import junit.framework.TestCase;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class LogoutHandlerTests extends TestCase {
    LogoutFilter filter;

    protected void setUp() throws Exception {
        filter = new LogoutFilter("/success", new LogoutHandler[] {new SecurityContextLogoutHandler()});
    }

    public void testRequiresLogoutUrlWorksWithPathParams() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        request.setRequestURI("/j_acegi_logout;someparam=blah?otherparam=blah");

        assertTrue(filter.requiresLogout(request, response));
    }

    public void testRequiresLogoutUrlWorksWithQueryParams() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContextPath("/context");
        MockHttpServletResponse response = new MockHttpServletResponse();

        request.setRequestURI("/context/j_acegi_logout?param=blah");

        assertTrue(filter.requiresLogout(request, response));
    }

}
