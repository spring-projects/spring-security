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
package org.acegisecurity.captcha;

import junit.framework.TestCase;

import org.acegisecurity.ConfigAttributeDefinition;
import org.acegisecurity.MockFilterChain;
import org.acegisecurity.SecurityConfig;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.intercept.web.FilterInvocation;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;

import javax.servlet.ServletException;


/**
 * Tests {@link org.acegisecurity.captcha.CaptchaChannelProcessorTemplate}
 *
 * @author marc antoine Garrigue
 * @version $Id$
 */
public class CaptchaChannelProcessorTemplateTests extends TestCase {
    //~ Methods ================================================================

    public void testContextRedirect() throws Exception {
        CaptchaChannelProcessorTemplate processor = new TestHumanityCaptchaChannelProcessor();
        processor.setKeyword("X");

        ConfigAttributeDefinition cad = new ConfigAttributeDefinition();
        cad.addConfigAttribute(new SecurityConfig("Y"));

        CaptchaSecurityContext context = new CaptchaSecurityContextImpl();
        SecurityContextHolder.setContext(context);

        CaptchaEntryPoint epoint = new CaptchaEntryPoint();
        epoint.setCaptchaFormUrl("/jcaptcha.do");
        epoint.setIncludeOriginalRequest(false);

        processor.setEntryPoint(epoint);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setQueryString("info=true");
        request.setServerName("localhost");
        request.setContextPath("/demo");
        request.setServletPath("/restricted");
        request.setScheme("http");
        request.setServerPort(8000);

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        FilterInvocation fi = new FilterInvocation(request, response, chain);

        processor.decide(fi, cad);
        assertEquals(null, response.getRedirectedUrl());
        processor.setKeyword("Y");
        response = decideWithNewResponse(cad, processor, request);
        assertEquals("http://localhost:8000/demo/jcaptcha.do",
            response.getRedirectedUrl());
        context.setHuman();
        response = decideWithNewResponse(cad, processor, request);
        assertEquals(null, response.getRedirectedUrl());
    }

    public void testDecideRejectsNulls() throws Exception {
        CaptchaChannelProcessorTemplate processor = new TestHumanityCaptchaChannelProcessor();
        processor.setEntryPoint(new CaptchaEntryPoint());
        processor.setKeyword("X");
        processor.afterPropertiesSet();

        try {
            processor.decide(null, null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testGettersSetters() {
        CaptchaChannelProcessorTemplate processor = new TestHumanityCaptchaChannelProcessor();
        assertEquals(null, processor.getKeyword());
        processor.setKeyword("X");
        assertEquals("X", processor.getKeyword());

        assertEquals(0, processor.getThresold());
        processor.setThresold(1);
        assertEquals(1, processor.getThresold());

        assertTrue(processor.getEntryPoint() == null);
        processor.setEntryPoint(new CaptchaEntryPoint());
        assertTrue(processor.getEntryPoint() != null);
    }

    public void testIncrementRequestCount() throws Exception {
        CaptchaChannelProcessorTemplate processor = new TestHumanityCaptchaChannelProcessor();
        processor.setKeyword("X");

        ConfigAttributeDefinition cad = new ConfigAttributeDefinition();
        cad.addConfigAttribute(new SecurityConfig("X"));

        CaptchaSecurityContext context = new CaptchaSecurityContextImpl();
        SecurityContextHolder.setContext(context);

        CaptchaEntryPoint epoint = new CaptchaEntryPoint();
        epoint.setCaptchaFormUrl("/jcaptcha.do");
        processor.setEntryPoint(epoint);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setQueryString("info=true");
        request.setServerName("localhost");
        request.setContextPath("/demo");
        request.setServletPath("/restricted");
        request.setScheme("http");
        request.setServerPort(8000);

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        FilterInvocation fi = new FilterInvocation(request, response, chain);

        processor.decide(fi, cad);
        assertEquals(0, context.getHumanRestrictedResourcesRequestsCount());
        context.setHuman();
        decideWithNewResponse(cad, processor, request);
        assertEquals(1, context.getHumanRestrictedResourcesRequestsCount());
        decideWithNewResponse(cad, processor, request);
        assertEquals(2, context.getHumanRestrictedResourcesRequestsCount());
        processor.setKeyword("Y");
        decideWithNewResponse(cad, processor, request);
        assertEquals(2, context.getHumanRestrictedResourcesRequestsCount());
        context = new CaptchaSecurityContextImpl();
        decideWithNewResponse(cad, processor, request);
        assertEquals(0, context.getHumanRestrictedResourcesRequestsCount());
    }

    public void testMissingEntryPoint() throws Exception {
        CaptchaChannelProcessorTemplate processor = new TestHumanityCaptchaChannelProcessor();
        processor.setEntryPoint(null);

        try {
            processor.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("entryPoint required", expected.getMessage());
        }
    }

    public void testMissingKeyword() throws Exception {
        CaptchaChannelProcessorTemplate processor = new TestHumanityCaptchaChannelProcessor();
        processor.setKeyword(null);

        try {
            processor.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {}

        processor.setKeyword("");

        try {
            processor.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {}
    }

    public void testSupports() {
        CaptchaChannelProcessorTemplate processor = new TestHumanityCaptchaChannelProcessor();
        processor.setKeyword("X");
        assertTrue(processor.supports(
                new SecurityConfig(processor.getKeyword())));

        assertTrue(processor.supports(new SecurityConfig("X")));

        assertFalse(processor.supports(null));

        assertFalse(processor.supports(new SecurityConfig("NOT_SUPPORTED")));
    }

    private MockHttpServletResponse decideWithNewResponse(
        ConfigAttributeDefinition cad,
        CaptchaChannelProcessorTemplate processor,
        MockHttpServletRequest request) throws IOException, ServletException {
        MockHttpServletResponse response;
        MockFilterChain chain;
        FilterInvocation fi;
        response = new MockHttpServletResponse();
        chain = new MockFilterChain();
        fi = new FilterInvocation(request, response, chain);
        processor.decide(fi, cad);

        return response;
    }

    //~ Inner Classes ==========================================================

    private class TestHumanityCaptchaChannelProcessor
        extends CaptchaChannelProcessorTemplate {
        boolean isContextValidConcerningHumanity(CaptchaSecurityContext context) {
            return context.isHuman();
        }
    }
}
