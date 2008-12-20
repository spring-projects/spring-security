/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.intercept.web;

import static org.junit.Assert.*;

import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.util.MockFilterChain;

/**
 * Tests {@link FilterInvocation}.
 *
 * @author Ben Alex
 * @author colin sampaleanu
 * @version $Id$
 */
public class FilterInvocationTests {

    //~ Methods ========================================================================================================

    @Test
    public void testGettersAndStringMethods() {
        MockHttpServletRequest request = new MockHttpServletRequest(null, null);
        request.setServletPath("/HelloWorld");
        request.setPathInfo("/some/more/segments.html");
        request.setServerName("www.example.com");
        request.setScheme("http");
        request.setServerPort(80);
        request.setContextPath("/mycontext");
        request.setRequestURI("/mycontext/HelloWorld/some/more/segments.html");

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        FilterInvocation fi = new FilterInvocation(request, response, chain);
        assertEquals(request, fi.getRequest());
        assertEquals(request, fi.getHttpRequest());
        assertEquals(response, fi.getResponse());
        assertEquals(response, fi.getHttpResponse());
        assertEquals(chain, fi.getChain());
        assertEquals("/HelloWorld/some/more/segments.html", fi.getRequestUrl());
        assertEquals("FilterInvocation: URL: /HelloWorld/some/more/segments.html", fi.toString());
        assertEquals("http://www.example.com/mycontext/HelloWorld/some/more/segments.html", fi.getFullRequestUrl());
    }

    @Test(expected=IllegalArgumentException.class)
    public void testRejectsNullFilterChain() {
        MockHttpServletRequest request = new MockHttpServletRequest(null, null);
        MockHttpServletResponse response = new MockHttpServletResponse();

        new FilterInvocation(request, response, null);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testRejectsNullServletRequest() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        new FilterInvocation(null, response, chain);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testRejectsNullServletResponse() {
        MockHttpServletRequest request = new MockHttpServletRequest(null, null);
        MockFilterChain chain = new MockFilterChain();

        new FilterInvocation(request, null, chain);
    }

    @Test
    public void testStringMethodsWithAQueryString() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setQueryString("foo=bar");
        request.setServletPath("/HelloWorld");
        request.setServerName("www.example.com");
        request.setScheme("http");
        request.setServerPort(80);
        request.setContextPath("/mycontext");
        request.setRequestURI("/mycontext/HelloWorld");

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        FilterInvocation fi = new FilterInvocation(request, response, chain);
        assertEquals("/HelloWorld?foo=bar", fi.getRequestUrl());
        assertEquals("FilterInvocation: URL: /HelloWorld?foo=bar", fi.toString());
        assertEquals("http://www.example.com/mycontext/HelloWorld?foo=bar", fi.getFullRequestUrl());
    }

    @Test
    public void testStringMethodsWithoutAnyQueryString() {
        MockHttpServletRequest request = new MockHttpServletRequest(null, null);
        request.setServletPath("/HelloWorld");
        request.setServerName("www.example.com");
        request.setScheme("http");
        request.setServerPort(80);
        request.setContextPath("/mycontext");
        request.setRequestURI("/mycontext/HelloWorld");

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        FilterInvocation fi = new FilterInvocation(request, response, chain);
        assertEquals("/HelloWorld", fi.getRequestUrl());
        assertEquals("FilterInvocation: URL: /HelloWorld", fi.toString());
        assertEquals("http://www.example.com/mycontext/HelloWorld", fi.getFullRequestUrl());
    }
}
