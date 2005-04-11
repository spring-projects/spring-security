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

package net.sf.acegisecurity.ui.webapp;

import junit.framework.TestCase;



import net.sf.acegisecurity.MockPortResolver;

import net.sf.acegisecurity.util.PortMapperImpl;

import java.util.HashMap;
import java.util.Map;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;


/**
 * Tests {@link AuthenticationProcessingFilterEntryPoint}.
 *
 * @author Ben Alex
 * @author colin sampaleanu
 * @version $Id$
 */
public class AuthenticationProcessingFilterEntryPointTests extends TestCase {
    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(AuthenticationProcessingFilterEntryPointTests.class);
    }

    public void testDetectsMissingLoginFormUrl() throws Exception {
        AuthenticationProcessingFilterEntryPoint ep = new AuthenticationProcessingFilterEntryPoint();
        ep.setPortMapper(new PortMapperImpl());
        ep.setPortResolver(new MockPortResolver(80, 443));

        try {
            ep.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("loginFormUrl must be specified", expected.getMessage());
        }
    }

    public void testDetectsMissingPortMapper() throws Exception {
        AuthenticationProcessingFilterEntryPoint ep = new AuthenticationProcessingFilterEntryPoint();
        ep.setLoginFormUrl("xxx");
        ep.setPortMapper(null);

        try {
            ep.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("portMapper must be specified", expected.getMessage());
        }
    }

    public void testDetectsMissingPortResolver() throws Exception {
        AuthenticationProcessingFilterEntryPoint ep = new AuthenticationProcessingFilterEntryPoint();
        ep.setLoginFormUrl("xxx");
        ep.setPortResolver(null);

        try {
            ep.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("portResolver must be specified", expected.getMessage());
        }
    }

    public void testGettersSetters() {
        AuthenticationProcessingFilterEntryPoint ep = new AuthenticationProcessingFilterEntryPoint();
        ep.setLoginFormUrl("/hello");
        ep.setPortMapper(new PortMapperImpl());
        ep.setPortResolver(new MockPortResolver(8080, 8443));
        assertEquals("/hello", ep.getLoginFormUrl());
        assertTrue(ep.getPortMapper() != null);
        assertTrue(ep.getPortResolver() != null);

        ep.setForceHttps(false);
        assertFalse(ep.getForceHttps());
        ep.setForceHttps(true);
        assertTrue(ep.getForceHttps());
    }

    public void testHttpsOperationFromOriginalHttpUrl()
        throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/some_path");
        request.setScheme("http");
        request.setServerName("www.example.com");
        request.setContextPath("/bigWebApp");
        request.setServerPort(80);

        MockHttpServletResponse response = new MockHttpServletResponse();

        AuthenticationProcessingFilterEntryPoint ep = new AuthenticationProcessingFilterEntryPoint();
        ep.setLoginFormUrl("/hello");
        ep.setPortMapper(new PortMapperImpl());
        ep.setForceHttps(true);
        ep.setPortMapper(new PortMapperImpl());
        ep.setPortResolver(new MockPortResolver(80, 443));
        ep.afterPropertiesSet();

        ep.commence(request, response, null);
        assertEquals("https://www.example.com/bigWebApp/hello",
            response.getRedirectedUrl());

        request.setServerPort(8080);
        response = new MockHttpServletResponse();
        ep.setPortResolver(new MockPortResolver(8080, 8443));
        ep.commence(request, response, null);
        assertEquals("https://www.example.com:8443/bigWebApp/hello",
            response.getRedirectedUrl());

        // Now test an unusual custom HTTP:HTTPS is handled properly
        request.setServerPort(8888);
        response = new MockHttpServletResponse();
        ep.commence(request, response, null);
        assertEquals("https://www.example.com:8443/bigWebApp/hello",
            response.getRedirectedUrl());

        PortMapperImpl portMapper = new PortMapperImpl();
        Map map = new HashMap();
        map.put("8888", "9999");
        portMapper.setPortMappings(map);
        response = new MockHttpServletResponse();

        ep = new AuthenticationProcessingFilterEntryPoint();
        ep.setLoginFormUrl("/hello");
        ep.setPortMapper(new PortMapperImpl());
        ep.setForceHttps(true);
        ep.setPortMapper(portMapper);
        ep.setPortResolver(new MockPortResolver(8888, 9999));
        ep.afterPropertiesSet();

        ep.commence(request, response, null);
        assertEquals("https://www.example.com:9999/bigWebApp/hello",
            response.getRedirectedUrl());
    }

    public void testHttpsOperationFromOriginalHttpsUrl()
        throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/some_path");
        request.setScheme("https");
        request.setServerName("www.example.com");
        request.setContextPath("/bigWebApp");
        request.setServerPort(443);

        MockHttpServletResponse response = new MockHttpServletResponse();

        AuthenticationProcessingFilterEntryPoint ep = new AuthenticationProcessingFilterEntryPoint();
        ep.setLoginFormUrl("/hello");
        ep.setPortMapper(new PortMapperImpl());
        ep.setForceHttps(true);
        ep.setPortMapper(new PortMapperImpl());
        ep.setPortResolver(new MockPortResolver(80, 443));
        ep.afterPropertiesSet();

        ep.commence(request, response, null);
        assertEquals("https://www.example.com/bigWebApp/hello",
            response.getRedirectedUrl());

        request.setServerPort(8443);
        response = new MockHttpServletResponse();
        ep.setPortResolver(new MockPortResolver(8080, 8443));
        ep.commence(request, response, null);
        assertEquals("https://www.example.com:8443/bigWebApp/hello",
            response.getRedirectedUrl());
    }

    public void testNormalOperation() throws Exception {
        AuthenticationProcessingFilterEntryPoint ep = new AuthenticationProcessingFilterEntryPoint();
        ep.setLoginFormUrl("/hello");
        ep.setPortMapper(new PortMapperImpl());
        ep.setPortResolver(new MockPortResolver(80, 443));
        ep.afterPropertiesSet();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/some_path");
        request.setContextPath("/bigWebApp");
        request.setScheme("http");
        request.setServerName("www.example.com");
        request.setContextPath("/bigWebApp");
        request.setServerPort(80);

        MockHttpServletResponse response = new MockHttpServletResponse();

        ep.afterPropertiesSet();
        ep.commence(request, response, null);
        assertEquals("http://www.example.com/bigWebApp/hello",
            response.getRedirectedUrl());
    }

    public void testOperationWhenHttpsRequestsButHttpsPortUnknown()
        throws Exception {
        AuthenticationProcessingFilterEntryPoint ep = new AuthenticationProcessingFilterEntryPoint();
        ep.setLoginFormUrl("/hello");
        ep.setPortMapper(new PortMapperImpl());
        ep.setPortResolver(new MockPortResolver(8888, 1234));
        ep.setForceHttps(true);
        ep.afterPropertiesSet();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/some_path");
        request.setContextPath("/bigWebApp");
        request.setScheme("http");
        request.setServerName("www.example.com");
        request.setContextPath("/bigWebApp");
        request.setServerPort(8888); // NB: Port we can't resolve

        MockHttpServletResponse response = new MockHttpServletResponse();

        ep.afterPropertiesSet();
        ep.commence(request, response, null);

        // Response doesn't switch to HTTPS, as we didn't know HTTP port 8888 to HTTP port mapping
        assertEquals("http://www.example.com:8888/bigWebApp/hello",
            response.getRedirectedUrl());
    }
}
