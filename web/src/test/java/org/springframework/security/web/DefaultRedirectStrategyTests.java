package org.springframework.security.web;

import static org.junit.Assert.*;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class DefaultRedirectStrategyTests {
    @Test
    public void contextRelativeUrlWithContextNameInHostnameIsHandledCorrectly() throws Exception {
        DefaultRedirectStrategy rds = new DefaultRedirectStrategy();
        rds.setContextRelative(true);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContextPath("/context");
        MockHttpServletResponse response = new MockHttpServletResponse();

        rds.sendRedirect(request, response, "http://context.blah.com/context/remainder");

        assertEquals("remainder", response.getRedirectedUrl());
    }
}
