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

package net.sf.acegisecurity.securechannel;

import junit.framework.TestCase;

import net.sf.acegisecurity.MockHttpServletRequest;
import net.sf.acegisecurity.MockHttpServletResponse;
import net.sf.acegisecurity.MockPortResolver;
import net.sf.acegisecurity.util.PortMapperImpl;

import java.util.HashMap;
import java.util.Map;


/**
 * Tests {@link RetryWithHttpEntryPoint}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class RetryWithHttpEntryPointTests extends TestCase {
    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(RetryWithHttpEntryPointTests.class);
    }

    public void testDetectsMissingPortMapper() throws Exception {
        RetryWithHttpEntryPoint ep = new RetryWithHttpEntryPoint();
        ep.setPortMapper(null);

        try {
            ep.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("portMapper is required", expected.getMessage());
        }
    }

    public void testDetectsMissingPortResolver() throws Exception {
        RetryWithHttpEntryPoint ep = new RetryWithHttpEntryPoint();
        ep.setPortResolver(null);

        try {
            ep.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("portResolver is required", expected.getMessage());
        }
    }

    public void testGettersSetters() {
        RetryWithHttpEntryPoint ep = new RetryWithHttpEntryPoint();
        ep.setPortMapper(new PortMapperImpl());
        ep.setPortResolver(new MockPortResolver(8080, 8443));
        assertTrue(ep.getPortMapper() != null);
        assertTrue(ep.getPortResolver() != null);
    }

    public void testNormalOperation() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("open=true");
        request.setScheme("https");
        request.setServerName("www.example.com");
        request.setContextPath("/bigWebApp");
        request.setServletPath("/hello");
        request.setPathInfo("/pathInfo.html");
        request.setServerPort(443);

        MockHttpServletResponse response = new MockHttpServletResponse();

        RetryWithHttpEntryPoint ep = new RetryWithHttpEntryPoint();
        ep.setPortMapper(new PortMapperImpl());
        ep.setPortResolver(new MockPortResolver(80, 443));
        ep.afterPropertiesSet();

        ep.commence(request, response);
        assertEquals("http://www.example.com/bigWebApp/hello/pathInfo.html?open=true",
            response.getRedirect());
    }

    public void testNormalOperationWithNullPathInfoAndNullQueryString()
        throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(null);
        request.setScheme("https");
        request.setServerName("www.example.com");
        request.setContextPath("/bigWebApp");
        request.setServletPath("/hello");
        request.setPathInfo(null);
        request.setServerPort(443);

        MockHttpServletResponse response = new MockHttpServletResponse();

        RetryWithHttpEntryPoint ep = new RetryWithHttpEntryPoint();
        ep.setPortMapper(new PortMapperImpl());
        ep.setPortResolver(new MockPortResolver(80, 443));
        ep.afterPropertiesSet();

        ep.commence(request, response);
        assertEquals("http://www.example.com/bigWebApp/hello",
            response.getRedirect());
    }

    public void testOperationWhenTargetPortIsUnknown()
        throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("open=true");
        request.setScheme("https");
        request.setServerName("www.example.com");
        request.setContextPath("/bigWebApp");
        request.setServletPath("/hello");
        request.setPathInfo("/pathInfo.html");
        request.setServerPort(8768);

        MockHttpServletResponse response = new MockHttpServletResponse();

        RetryWithHttpEntryPoint ep = new RetryWithHttpEntryPoint();
        ep.setPortMapper(new PortMapperImpl());
        ep.setPortResolver(new MockPortResolver(8768, 1234));
        ep.afterPropertiesSet();

        ep.commence(request, response);
        assertEquals("/bigWebApp", response.getRedirect());
    }

    public void testOperationWithNonStandardPort() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("open=true");
        request.setScheme("https");
        request.setServerName("www.example.com");
        request.setContextPath("/bigWebApp");
        request.setServletPath("/hello");
        request.setPathInfo("/pathInfo.html");
        request.setServerPort(9999);

        MockHttpServletResponse response = new MockHttpServletResponse();

        PortMapperImpl portMapper = new PortMapperImpl();
        Map map = new HashMap();
        map.put("8888", "9999");
        portMapper.setPortMappings(map);

        RetryWithHttpEntryPoint ep = new RetryWithHttpEntryPoint();
        ep.setPortResolver(new MockPortResolver(8888, 9999));
        ep.setPortMapper(portMapper);
        ep.afterPropertiesSet();

        ep.commence(request, response);
        assertEquals("http://www.example.com:8888/bigWebApp/hello/pathInfo.html?open=true",
            response.getRedirect());
    }
}
