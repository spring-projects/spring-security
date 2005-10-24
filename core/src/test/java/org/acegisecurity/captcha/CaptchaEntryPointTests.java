/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.captcha;

import junit.framework.TestCase;

import net.sf.acegisecurity.MockPortResolver;
import net.sf.acegisecurity.util.PortMapperImpl;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.net.URLEncoder;

import java.util.HashMap;
import java.util.Map;


/**
 * Tests {@link CaptchaEntryPoint}.
 *
 * @author marc antoine Garrigue
 * @version $Id$
 */
public class CaptchaEntryPointTests extends TestCase {
    //~ Methods ================================================================

    // ~ Methods
    // ================================================================
    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(CaptchaEntryPointTests.class);
    }

    public void testDetectsMissingCaptchaFormUrl() throws Exception {
        CaptchaEntryPoint ep = new CaptchaEntryPoint();
        ep.setPortMapper(new PortMapperImpl());
        ep.setPortResolver(new MockPortResolver(80, 443));

        try {
            ep.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("captchaFormUrl must be specified",
                expected.getMessage());
        }
    }

    public void testDetectsMissingPortMapper() throws Exception {
        CaptchaEntryPoint ep = new CaptchaEntryPoint();
        ep.setCaptchaFormUrl("xxx");
        ep.setPortMapper(null);

        try {
            ep.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("portMapper must be specified", expected.getMessage());
        }
    }

    public void testDetectsMissingPortResolver() throws Exception {
        CaptchaEntryPoint ep = new CaptchaEntryPoint();
        ep.setCaptchaFormUrl("xxx");
        ep.setPortResolver(null);

        try {
            ep.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("portResolver must be specified", expected.getMessage());
        }
    }

    public void testGettersSetters() {
        CaptchaEntryPoint ep = new CaptchaEntryPoint();
        ep.setCaptchaFormUrl("/hello");
        ep.setPortMapper(new PortMapperImpl());
        ep.setPortResolver(new MockPortResolver(8080, 8443));
        assertEquals("/hello", ep.getCaptchaFormUrl());
        assertTrue(ep.getPortMapper() != null);
        assertTrue(ep.getPortResolver() != null);

        assertEquals("original_requestUrl",
            ep.getOriginalRequestUrlParameterName());
        ep.setOriginalRequestUrlParameterName("Z");
        assertEquals("Z", ep.getOriginalRequestUrlParameterName());

        assertEquals(true, ep.isIncludeOriginalRequest());
        ep.setIncludeOriginalRequest(false);
        assertEquals(false, ep.isIncludeOriginalRequest());

        assertEquals(false, ep.isOutsideWebApp());
        ep.setOutsideWebApp(true);
        assertEquals(true, ep.isOutsideWebApp());

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

        CaptchaEntryPoint ep = new CaptchaEntryPoint();
        ep.setIncludeOriginalRequest(false);
        ep.setCaptchaFormUrl("/hello");
        ep.setPortMapper(new PortMapperImpl());
        ep.setForceHttps(true);
        ep.setPortMapper(new PortMapperImpl());
        ep.setPortResolver(new MockPortResolver(80, 443));
        ep.afterPropertiesSet();

        ep.commence(request, response);
        assertEquals("https://www.example.com/bigWebApp/hello",
            response.getRedirectedUrl());

        request.setServerPort(8080);
        response = new MockHttpServletResponse();
        ep.setPortResolver(new MockPortResolver(8080, 8443));
        ep.commence(request, response);
        assertEquals("https://www.example.com:8443/bigWebApp/hello",
            response.getRedirectedUrl());

        // Now test an unusual custom HTTP:HTTPS is handled properly
        request.setServerPort(8888);
        response = new MockHttpServletResponse();
        ep.commence(request, response);
        assertEquals("https://www.example.com:8443/bigWebApp/hello",
            response.getRedirectedUrl());

        PortMapperImpl portMapper = new PortMapperImpl();
        Map map = new HashMap();
        map.put("8888", "9999");
        portMapper.setPortMappings(map);
        response = new MockHttpServletResponse();

        ep = new CaptchaEntryPoint();
        ep.setCaptchaFormUrl("/hello");
        ep.setPortMapper(new PortMapperImpl());
        ep.setForceHttps(true);
        ep.setPortMapper(portMapper);
        ep.setPortResolver(new MockPortResolver(8888, 9999));
        ep.setIncludeOriginalRequest(false);

        ep.afterPropertiesSet();

        ep.commence(request, response);
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

        CaptchaEntryPoint ep = new CaptchaEntryPoint();
        ep.setIncludeOriginalRequest(false);
        ep.setCaptchaFormUrl("/hello");
        ep.setPortMapper(new PortMapperImpl());
        ep.setForceHttps(true);
        ep.setPortMapper(new PortMapperImpl());
        ep.setPortResolver(new MockPortResolver(80, 443));
        ep.afterPropertiesSet();

        ep.commence(request, response);
        assertEquals("https://www.example.com/bigWebApp/hello",
            response.getRedirectedUrl());

        request.setServerPort(8443);
        response = new MockHttpServletResponse();
        ep.setPortResolver(new MockPortResolver(8080, 8443));
        ep.commence(request, response);
        assertEquals("https://www.example.com:8443/bigWebApp/hello",
            response.getRedirectedUrl());
    }

    public void testNormalOperation() throws Exception {
        CaptchaEntryPoint ep = new CaptchaEntryPoint();
        ep.setCaptchaFormUrl("/hello");
        ep.setPortMapper(new PortMapperImpl());
        ep.setPortResolver(new MockPortResolver(80, 443));
        ep.afterPropertiesSet();
        ep.setIncludeOriginalRequest(false);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/some_path");
        request.setContextPath("/bigWebApp");
        request.setScheme("http");
        request.setServerName("www.example.com");
        request.setContextPath("/bigWebApp");
        request.setServerPort(80);

        MockHttpServletResponse response = new MockHttpServletResponse();

        ep.afterPropertiesSet();
        ep.commence(request, response);
        assertEquals("http://www.example.com/bigWebApp/hello",
            response.getRedirectedUrl());
    }

    public void testOperationWhenHttpsRequestsButHttpsPortUnknown()
        throws Exception {
        CaptchaEntryPoint ep = new CaptchaEntryPoint();
        ep.setCaptchaFormUrl("/hello");
        ep.setPortMapper(new PortMapperImpl());
        ep.setPortResolver(new MockPortResolver(8888, 1234));
        ep.setForceHttps(true);
        ep.setIncludeOriginalRequest(false);

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
        ep.commence(request, response);

        // Response doesn't switch to HTTPS, as we didn't know HTTP port 8888 to
        // HTTP port mapping
        assertEquals("http://www.example.com:8888/bigWebApp/hello",
            response.getRedirectedUrl());
    }

    public void testOperationWithOriginalRequestIncludes()
        throws Exception {
        CaptchaEntryPoint ep = new CaptchaEntryPoint();
        ep.setCaptchaFormUrl("/hello");

        PortMapperImpl mapper = new PortMapperImpl();
        mapper.getTranslatedPortMappings().put(new Integer(8888),
            new Integer(1234));
        ep.setPortMapper(mapper);

        ep.setPortResolver(new MockPortResolver(8888, 1234));
        ep.setIncludeOriginalRequest(true);
        ep.afterPropertiesSet();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("post");
        request.setRequestURI("/some_path");
        request.setScheme("http");
        request.setServerName("www.example.com");

        // request.setContextPath("/bigWebApp");
        // TODO correct this when the getRequestUrl from mock works...
        request.setServerPort(8888); // NB: Port we can't resolve

        MockHttpServletResponse response = new MockHttpServletResponse();

        ep.afterPropertiesSet();
        ep.commence(request, response);
        assertEquals("http://www.example.com:8888/hello?original_requestUrl="
            + URLEncoder.encode("http://www.example.com:8888/some_path", "UTF-8")
            + "&original_request_method=post", response.getRedirectedUrl());

        // test the query params
        request.addParameter("name", "value");
        response = new MockHttpServletResponse();
        ep.commence(request, response);
        assertEquals("http://www.example.com:8888/hello?original_requestUrl="
            + URLEncoder.encode("http://www.example.com:8888/some_path", "UTF-8")
            + "&original_request_method=post", response.getRedirectedUrl());

        // test the multiple query params
        ep.setIncludeOriginalParameters(true);

        request.addParameter("name", "value");
        request.addParameter("name1", "value2");
        response = new MockHttpServletResponse();
        ep.commence(request, response);
        assertEquals("http://www.example.com:8888/hello?original_requestUrl="
            + URLEncoder.encode("http://www.example.com:8888/some_path", "UTF-8")
            + "&original_request_method=post" + "&original_request_parameters="
            + URLEncoder.encode("name__value;;name1__value2", "UTF-8"),
            response.getRedirectedUrl());

        // test add parameter to captcha form url??
        ep.setCaptchaFormUrl("/hello?toto=titi");
        response = new MockHttpServletResponse();
        ep.commence(request, response);
        assertEquals(
            "http://www.example.com:8888/hello?toto=titi&original_requestUrl="
            + URLEncoder.encode("http://www.example.com:8888/some_path", "UTF-8")
            + "&original_request_method=post" + "&original_request_parameters="
            + URLEncoder.encode("name__value;;name1__value2", "UTF-8"),
            response.getRedirectedUrl());

        // with forcing!!!
        ep.setForceHttps(true);
        response = new MockHttpServletResponse();
        ep.commence(request, response);
        assertEquals(
            "https://www.example.com:1234/hello?toto=titi&original_requestUrl="
            + URLEncoder.encode("http://www.example.com:8888/some_path", "UTF-8")
            + "&original_request_method=post" + "&original_request_parameters="
            + URLEncoder.encode("name__value;;name1__value2", "UTF-8"),
            response.getRedirectedUrl());
    }

    public void testOperationWithOutsideWebApp() throws Exception {
        CaptchaEntryPoint ep = new CaptchaEntryPoint();
        ep.setCaptchaFormUrl("https://www.jcaptcha.net/dotest/");

        PortMapperImpl mapper = new PortMapperImpl();
        mapper.getTranslatedPortMappings().put(new Integer(8888),
            new Integer(1234));
        ep.setPortMapper(mapper);

        ep.setPortResolver(new MockPortResolver(8888, 1234));
        ep.setIncludeOriginalRequest(true);
        ep.setOutsideWebApp(true);

        ep.afterPropertiesSet();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/some_path");
        request.setScheme("http");
        request.setServerName("www.example.com");
        request.setMethod("post");

        // request.setContextPath("/bigWebApp");
        // TODO correct this when the getRequestUrl from mock works...
        request.setServerPort(8888); // NB: Port we can't resolve

        MockHttpServletResponse response = new MockHttpServletResponse();

        ep.afterPropertiesSet();
        ep.commence(request, response);
        assertEquals("https://www.jcaptcha.net/dotest/?original_requestUrl="
            + URLEncoder.encode("http://www.example.com:8888/some_path", "UTF-8")
            + "&original_request_method=post", response.getRedirectedUrl());

        // test the query params
        request.addParameter("name", "value");
        response = new MockHttpServletResponse();
        ep.commence(request, response);
        assertEquals("https://www.jcaptcha.net/dotest/?original_requestUrl="
            + URLEncoder.encode("http://www.example.com:8888/some_path", "UTF-8")
            + "&original_request_method=post", response.getRedirectedUrl());

        // test the multiple query params
        ep.setIncludeOriginalParameters(true);
        request.addParameter("name", "value");
        request.addParameter("name1", "value2");
        response = new MockHttpServletResponse();
        ep.commence(request, response);
        assertEquals("https://www.jcaptcha.net/dotest/?original_requestUrl="
            + URLEncoder.encode("http://www.example.com:8888/some_path", "UTF-8")
            + "&original_request_method=post" + "&original_request_parameters="
            + URLEncoder.encode("name__value;;name1__value2", "UTF-8"),
            response.getRedirectedUrl());

        // test add parameter to captcha form url??
        ep.setCaptchaFormUrl("https://www.jcaptcha.net/dotest/?toto=titi");
        response = new MockHttpServletResponse();
        ep.commence(request, response);
        assertEquals(
            "https://www.jcaptcha.net/dotest/?toto=titi&original_requestUrl="
            + URLEncoder.encode("http://www.example.com:8888/some_path", "UTF-8")
            + "&original_request_method=post" + "&original_request_parameters="
            + URLEncoder.encode("name__value;;name1__value2", "UTF-8"),
            response.getRedirectedUrl());

        // with forcing!!!
        ep.setForceHttps(true);
        response = new MockHttpServletResponse();
        ep.commence(request, response);
        assertEquals(
            "https://www.jcaptcha.net/dotest/?toto=titi&original_requestUrl="
            + URLEncoder.encode("http://www.example.com:8888/some_path", "UTF-8")
            + "&original_request_method=post" + "&original_request_parameters="
            + URLEncoder.encode("name__value;;name1__value2", "UTF-8"),
            response.getRedirectedUrl());
    }
}
