/*
 * Copyright 2010 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.util.matcher;

import static org.junit.Assert.*;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.util.matcher.ELRequestMatcher;

/**
 * @author Mike Wiesner
 * @since 3.0.2
 */
public class ELRequestMatcherTests {

    @Test
    public void testHasIpAddressTrue() throws Exception {
        ELRequestMatcher requestMatcher = new ELRequestMatcher("hasIpAddress('1.1.1.1')");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("1.1.1.1");

        assertTrue(requestMatcher.matches(request));
    }

    @Test
    public void testHasIpAddressFalse() throws Exception {
        ELRequestMatcher requestMatcher = new ELRequestMatcher("hasIpAddress('1.1.1.1')");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("1.1.1.2");

        assertFalse(requestMatcher.matches(request));
    }

    @Test
    public void testHasHeaderTrue() throws Exception {
        ELRequestMatcher requestMatcher = new ELRequestMatcher("hasHeader('User-Agent','MSIE')");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("User-Agent", "MSIE");

        assertTrue(requestMatcher.matches(request));
    }

    @Test
    public void testHasHeaderTwoEntries() throws Exception {
        ELRequestMatcher requestMatcher = new ELRequestMatcher(
                "hasHeader('User-Agent','MSIE') or hasHeader('User-Agent','Mozilla')");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("User-Agent", "MSIE");

        assertTrue(requestMatcher.matches(request));

        request = new MockHttpServletRequest();
        request.addHeader("User-Agent", "Mozilla");

        assertTrue(requestMatcher.matches(request));

    }

    @Test
    public void testHasHeaderFalse() throws Exception {
        ELRequestMatcher requestMatcher = new ELRequestMatcher("hasHeader('User-Agent','MSIE')");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("User-Agent", "wrong");

        assertFalse(requestMatcher.matches(request));
    }

    @Test
    public void testHasHeaderNull() throws Exception {
        ELRequestMatcher requestMatcher = new ELRequestMatcher("hasHeader('User-Agent','MSIE')");
        MockHttpServletRequest request = new MockHttpServletRequest();

        assertFalse(requestMatcher.matches(request));
    }

}
