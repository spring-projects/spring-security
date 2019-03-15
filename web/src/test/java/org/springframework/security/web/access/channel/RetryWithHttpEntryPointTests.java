/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.access.channel;

import static org.mockito.Mockito.mock;

import junit.framework.TestCase;

import org.springframework.security.MockPortResolver;

import org.springframework.security.web.PortMapper;
import org.springframework.security.web.PortMapperImpl;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.access.channel.RetryWithHttpEntryPoint;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.HashMap;
import java.util.Map;


/**
 * Tests {@link RetryWithHttpEntryPoint}.
 *
 * @author Ben Alex
 */
public class RetryWithHttpEntryPointTests extends TestCase {
    //~ Methods ========================================================================================================

    public void testDetectsMissingPortMapper() throws Exception {
        RetryWithHttpEntryPoint ep = new RetryWithHttpEntryPoint();

        try {
            ep.setPortMapper(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }
    }

    public void testDetectsMissingPortResolver() throws Exception {
        RetryWithHttpEntryPoint ep = new RetryWithHttpEntryPoint();

        try {
            ep.setPortResolver(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }
    }

    public void testGettersSetters() {
        RetryWithHttpEntryPoint ep = new RetryWithHttpEntryPoint();
        PortMapper portMapper = mock(PortMapper.class);
        PortResolver portResolver = mock(PortResolver.class);
        RedirectStrategy redirector = mock(RedirectStrategy.class);
        ep.setPortMapper(portMapper);
        ep.setPortResolver(portResolver);
        ep.setRedirectStrategy(redirector);
        assertSame(portMapper, ep.getPortMapper());
        assertSame(portResolver, ep.getPortResolver());
        assertSame(redirector, ep.getRedirectStrategy());
    }

    public void testNormalOperation() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/bigWebApp/hello/pathInfo.html");
        request.setQueryString("open=true");
        request.setScheme("https");
        request.setServerName("www.example.com");
        request.setServerPort(443);

        MockHttpServletResponse response = new MockHttpServletResponse();

        RetryWithHttpEntryPoint ep = new RetryWithHttpEntryPoint();
        ep.setPortMapper(new PortMapperImpl());
        ep.setPortResolver(new MockPortResolver(80, 443));

        ep.commence(request, response);
        assertEquals("http://www.example.com/bigWebApp/hello/pathInfo.html?open=true", response.getRedirectedUrl());
    }

    public void testNormalOperationWithNullQueryString() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/bigWebApp/hello");
        request.setScheme("https");
        request.setServerName("www.example.com");
        request.setServerPort(443);

        MockHttpServletResponse response = new MockHttpServletResponse();

        RetryWithHttpEntryPoint ep = new RetryWithHttpEntryPoint();
        ep.setPortMapper(new PortMapperImpl());
        ep.setPortResolver(new MockPortResolver(80, 443));

        ep.commence(request, response);
        assertEquals("http://www.example.com/bigWebApp/hello", response.getRedirectedUrl());
    }

    public void testOperationWhenTargetPortIsUnknown() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/bigWebApp");
        request.setQueryString("open=true");
        request.setScheme("https");
        request.setServerName("www.example.com");
        request.setServerPort(8768);

        MockHttpServletResponse response = new MockHttpServletResponse();

        RetryWithHttpEntryPoint ep = new RetryWithHttpEntryPoint();
        ep.setPortMapper(new PortMapperImpl());
        ep.setPortResolver(new MockPortResolver(8768, 1234));

        ep.commence(request, response);
        assertEquals("/bigWebApp?open=true", response.getRedirectedUrl());
    }

    public void testOperationWithNonStandardPort() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/bigWebApp/hello/pathInfo.html");
        request.setQueryString("open=true");
        request.setScheme("https");
        request.setServerName("www.example.com");
        request.setServerPort(9999);

        MockHttpServletResponse response = new MockHttpServletResponse();

        PortMapperImpl portMapper = new PortMapperImpl();
        Map<String, String> map = new HashMap<String, String>();
        map.put("8888", "9999");
        portMapper.setPortMappings(map);

        RetryWithHttpEntryPoint ep = new RetryWithHttpEntryPoint();
        ep.setPortResolver(new MockPortResolver(8888, 9999));
        ep.setPortMapper(portMapper);

        ep.commence(request, response);
        assertEquals("http://www.example.com:8888/bigWebApp/hello/pathInfo.html?open=true", response.getRedirectedUrl());
    }
}
