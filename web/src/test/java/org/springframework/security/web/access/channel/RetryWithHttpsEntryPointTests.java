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

package org.springframework.security.web.access.channel;

import junit.framework.TestCase;

import org.springframework.security.MockPortResolver;

import org.springframework.security.web.PortMapperImpl;
import org.springframework.security.web.access.channel.RetryWithHttpsEntryPoint;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.HashMap;
import java.util.Map;


/**
 * Tests {@link RetryWithHttpsEntryPoint}.
 *
 * @author Ben Alex
 */
public class RetryWithHttpsEntryPointTests extends TestCase {
    //~ Methods ========================================================================================================

    public void testDetectsMissingPortMapper() throws Exception {
        RetryWithHttpsEntryPoint ep = new RetryWithHttpsEntryPoint();

        try {
            ep.setPortMapper(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }
    }

    public void testDetectsMissingPortResolver() throws Exception {
        RetryWithHttpsEntryPoint ep = new RetryWithHttpsEntryPoint();

        try {
            ep.setPortResolver(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }
    }

    public void testGettersSetters() {
        RetryWithHttpsEntryPoint ep = new RetryWithHttpsEntryPoint();
        ep.setPortMapper(new PortMapperImpl());
        ep.setPortResolver(new MockPortResolver(8080, 8443));
        assertTrue(ep.getPortMapper() != null);
        assertTrue(ep.getPortResolver() != null);
    }

    public void testNormalOperation() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/bigWebApp/hello/pathInfo.html");
        request.setQueryString("open=true");
        request.setScheme("http");
        request.setServerName("www.example.com");
        request.setServerPort(80);

        MockHttpServletResponse response = new MockHttpServletResponse();

        RetryWithHttpsEntryPoint ep = new RetryWithHttpsEntryPoint();
        ep.setPortMapper(new PortMapperImpl());
        ep.setPortResolver(new MockPortResolver(80, 443));

        ep.commence(request, response);
        assertEquals("https://www.example.com/bigWebApp/hello/pathInfo.html?open=true", response.getRedirectedUrl());
    }

    public void testNormalOperationWithNullQueryString() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/bigWebApp/hello");
        request.setScheme("http");
        request.setServerName("www.example.com");
        request.setServerPort(80);

        MockHttpServletResponse response = new MockHttpServletResponse();

        RetryWithHttpsEntryPoint ep = new RetryWithHttpsEntryPoint();
        ep.setPortMapper(new PortMapperImpl());
        ep.setPortResolver(new MockPortResolver(80, 443));

        ep.commence(request, response);
        assertEquals("https://www.example.com/bigWebApp/hello", response.getRedirectedUrl());
    }

    public void testOperationWhenTargetPortIsUnknown() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/bigWebApp");
        request.setQueryString("open=true");
        request.setScheme("http");
        request.setServerName("www.example.com");
        request.setServerPort(8768);

        MockHttpServletResponse response = new MockHttpServletResponse();

        RetryWithHttpsEntryPoint ep = new RetryWithHttpsEntryPoint();
        ep.setPortMapper(new PortMapperImpl());
        ep.setPortResolver(new MockPortResolver(8768, 1234));

        ep.commence(request, response);
        assertEquals("/bigWebApp?open=true", response.getRedirectedUrl());
    }

    public void testOperationWithNonStandardPort() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/bigWebApp/hello/pathInfo.html");
        request.setQueryString("open=true");
        request.setScheme("http");
        request.setServerName("www.example.com");
        request.setServerPort(8888);

        MockHttpServletResponse response = new MockHttpServletResponse();

        PortMapperImpl portMapper = new PortMapperImpl();
        Map<String, String> map = new HashMap<String, String>();
        map.put("8888", "9999");
        portMapper.setPortMappings(map);

        RetryWithHttpsEntryPoint ep = new RetryWithHttpsEntryPoint();
        ep.setPortResolver(new MockPortResolver(8888, 9999));
        ep.setPortMapper(portMapper);

        ep.commence(request, response);
        assertEquals("https://www.example.com:9999/bigWebApp/hello/pathInfo.html?open=true", response.getRedirectedUrl());
    }
}
