package org.springframework.security.web.util;

import static org.junit.Assert.*;

import org.junit.*;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * @author Luke Taylor
 */
public class RegexRequestMatcherTests {

    @Test
    public void doesntMatchIfHttpMethodIsDifferent() throws Exception {
        RegexRequestMatcher matcher = new RegexRequestMatcher(".*", "GET");

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/anything");

        assertFalse(matcher.matches(request));
    }

    @Test
    public void matchesIfHttpMethodAndPathMatch() throws Exception {
        RegexRequestMatcher matcher = new RegexRequestMatcher(".*", "GET");

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/anything");
        request.setServletPath("/anything");

        assertTrue(matcher.matches(request));
    }

    @Test
    public void queryStringIsMatcherCorrectly() throws Exception {
        RegexRequestMatcher matcher = new RegexRequestMatcher(".*\\?x=y", "GET");

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/any/path?x=y");
        request.setServletPath("/any");
        request.setPathInfo("/path");
        request.setQueryString("x=y");

        assertTrue(matcher.matches(request));
    }
}
