/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.intercept.web;

import junit.framework.TestCase;

import net.sf.acegisecurity.MockFilterChain;
import net.sf.acegisecurity.MockHttpServletRequest;
import net.sf.acegisecurity.MockHttpServletResponse;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;

import java.util.Enumeration;
import java.util.Locale;
import java.util.Map;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


/**
 * Tests {@link FilterInvocation}.
 *
 * @author Ben Alex
 * @author colin sampaleanu
 * @version $Id$
 */
public class FilterInvocationTests extends TestCase {
    //~ Constructors ===========================================================

    public FilterInvocationTests() {
        super();
    }

    public FilterInvocationTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(FilterInvocationTests.class);
    }

    public void testGettersAndStringMethods() {
        MockHttpServletRequest request = new MockHttpServletRequest(null, null);
        request.setServletPath("/HelloWorld");
        request.setPathInfo("/some/more/segments.html");
        request.setRequestURL("http://www.example.com/mycontext/HelloWorld/some/more/segments.html");

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
        assertEquals("http://www.example.com/mycontext/HelloWorld/some/more/segments.html",
            fi.getFullRequestUrl());
    }

    public void testNoArgsConstructor() {
        try {
            new FilterInvocation();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testRejectsNullFilterChain() {
        MockHttpServletRequest request = new MockHttpServletRequest(null, null);
        MockHttpServletResponse response = new MockHttpServletResponse();

        try {
            new FilterInvocation(request, response, null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testRejectsNullServletRequest() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        try {
            new FilterInvocation(null, response, chain);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testRejectsNullServletResponse() {
        MockHttpServletRequest request = new MockHttpServletRequest(null, null);
        MockFilterChain chain = new MockFilterChain();

        try {
            new FilterInvocation(request, null, chain);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testRejectsServletRequestWhichIsNotHttpServletRequest() {
        MockServletRequest request = new MockServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        try {
            new FilterInvocation(request, response, chain);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("Can only process HttpServletRequest",
                expected.getMessage());
        }
    }

    public void testRejectsServletResponseWhichIsNotHttpServletResponse() {
        MockHttpServletRequest request = new MockHttpServletRequest(null, null);
        MockServletResponse response = new MockServletResponse();
        MockFilterChain chain = new MockFilterChain();

        try {
            new FilterInvocation(request, response, chain);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("Can only process HttpServletResponse",
                expected.getMessage());
        }
    }

    public void testStringMethodsWithAQueryString() {
        MockHttpServletRequest request = new MockHttpServletRequest("foo=bar");
        request.setServletPath("/HelloWorld");
        request.setRequestURL("http://www.example.com/mycontext/HelloWorld");

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        FilterInvocation fi = new FilterInvocation(request, response, chain);
        assertEquals("/HelloWorld?foo=bar", fi.getRequestUrl());
        assertEquals("FilterInvocation: URL: /HelloWorld?foo=bar", fi.toString());
        assertEquals("http://www.example.com/mycontext/HelloWorld?foo=bar",
            fi.getFullRequestUrl());
    }

    public void testStringMethodsWithoutAnyQueryString() {
        MockHttpServletRequest request = new MockHttpServletRequest(null, null);
        request.setServletPath("/HelloWorld");
        request.setRequestURL("http://www.example.com/mycontext/HelloWorld");

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        FilterInvocation fi = new FilterInvocation(request, response, chain);
        assertEquals("/HelloWorld", fi.getRequestUrl());
        assertEquals("FilterInvocation: URL: /HelloWorld", fi.toString());
        assertEquals("http://www.example.com/mycontext/HelloWorld",
            fi.getFullRequestUrl());
    }

    //~ Inner Classes ==========================================================

    private class MockServletRequest implements ServletRequest {
        public void setAttribute(String arg0, Object arg1) {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public Object getAttribute(String arg0) {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public Enumeration getAttributeNames() {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public void setCharacterEncoding(String arg0)
            throws UnsupportedEncodingException {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public String getCharacterEncoding() {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public int getContentLength() {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public String getContentType() {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public ServletInputStream getInputStream() throws IOException {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public Locale getLocale() {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public Enumeration getLocales() {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public String getParameter(String arg0) {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public Map getParameterMap() {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public Enumeration getParameterNames() {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public String[] getParameterValues(String arg0) {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public String getProtocol() {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public BufferedReader getReader() throws IOException {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public String getRealPath(String arg0) {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public String getRemoteAddr() {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public String getRemoteHost() {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public RequestDispatcher getRequestDispatcher(String arg0) {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public String getScheme() {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public boolean isSecure() {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public String getServerName() {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public int getServerPort() {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public void removeAttribute(String arg0) {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }
    }

    private class MockServletResponse implements ServletResponse {
        public void setBufferSize(int arg0) {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public int getBufferSize() {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public String getCharacterEncoding() {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public boolean isCommitted() {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public void setContentLength(int arg0) {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public void setContentType(String arg0) {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public void setLocale(Locale arg0) {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public Locale getLocale() {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public ServletOutputStream getOutputStream() throws IOException {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public PrintWriter getWriter() throws IOException {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public void flushBuffer() throws IOException {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public void reset() {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public void resetBuffer() {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }
    }
}
