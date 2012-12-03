/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.web.util;

import static org.junit.Assert.*;

import org.junit.*;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * @author Luke Taylor
 * @author Rob Winch
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

    @Test
    public void requestHasNullMethodMatches() {
        RegexRequestMatcher matcher = new RegexRequestMatcher("/something/.*", "GET");
        MockHttpServletRequest request = createRequest("/something/here");
        request.setMethod(null);
        assertTrue(matcher.matches(request));
    }

    // SEC-2084
    @Test
    public void requestHasNullMethodNoMatch() {
        RegexRequestMatcher matcher = new RegexRequestMatcher("/something/.*", "GET");
        MockHttpServletRequest request = createRequest("/nomatch");
        request.setMethod(null);
        assertFalse(matcher.matches(request));
    }

    @Test
    public void requestHasNullMethodAndNullMatcherMatches() {
        RegexRequestMatcher matcher = new RegexRequestMatcher("/something/.*", null);
        MockHttpServletRequest request = createRequest("/something/here");
        request.setMethod(null);
        assertTrue(matcher.matches(request));
    }

    @Test
    public void requestHasNullMethodAndNullMatcherNoMatch() {
        RegexRequestMatcher matcher = new RegexRequestMatcher("/something/.*", null);
        MockHttpServletRequest request = createRequest("/nomatch");
        request.setMethod(null);
        assertFalse(matcher.matches(request));
    }

    private MockHttpServletRequest createRequest(String path) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setQueryString("doesntMatter");
        request.setServletPath(path);
        request.setMethod("POST");

        return request;
    }
}
