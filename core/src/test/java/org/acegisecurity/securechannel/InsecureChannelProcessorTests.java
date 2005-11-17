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

package org.acegisecurity.securechannel;

import junit.framework.TestCase;

import org.acegisecurity.ConfigAttributeDefinition;
import org.acegisecurity.MockFilterChain;


import org.acegisecurity.SecurityConfig;

import org.acegisecurity.intercept.web.FilterInvocation;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;


/**
 * Tests {@link InsecureChannelProcessor}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class InsecureChannelProcessorTests extends TestCase {
    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(InsecureChannelProcessorTests.class);
    }

    public void testDecideDetectsAcceptableChannel() throws Exception {
        ConfigAttributeDefinition cad = new ConfigAttributeDefinition();
        cad.addConfigAttribute(new SecurityConfig("SOME_IGNORED_ATTRIBUTE"));
        cad.addConfigAttribute(new SecurityConfig("REQUIRES_INSECURE_CHANNEL"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setQueryString("info=true");
        request.setServerName("localhost");
        request.setContextPath("/bigapp");
        request.setServletPath("/servlet");
        request.setScheme("http");
        request.setServerPort(8080);

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        FilterInvocation fi = new FilterInvocation(request, response, chain);

        InsecureChannelProcessor processor = new InsecureChannelProcessor();
        processor.decide(fi, cad);

        assertFalse(fi.getResponse().isCommitted());
    }

    public void testDecideDetectsUnacceptableChannel()
        throws Exception {
        ConfigAttributeDefinition cad = new ConfigAttributeDefinition();
        cad.addConfigAttribute(new SecurityConfig("SOME_IGNORED_ATTRIBUTE"));
        cad.addConfigAttribute(new SecurityConfig("REQUIRES_INSECURE_CHANNEL"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setQueryString("info=true");
        request.setServerName("localhost");
        request.setContextPath("/bigapp");
        request.setServletPath("/servlet");
        request.setScheme("https");
        request.setSecure(true);
        request.setServerPort(8443);

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        FilterInvocation fi = new FilterInvocation(request, response, chain);

        InsecureChannelProcessor processor = new InsecureChannelProcessor();
        processor.decide(fi, cad);

        assertTrue(fi.getResponse().isCommitted());
    }

    public void testDecideRejectsNulls() throws Exception {
        InsecureChannelProcessor processor = new InsecureChannelProcessor();
        processor.afterPropertiesSet();

        try {
            processor.decide(null, null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testGettersSetters() {
        InsecureChannelProcessor processor = new InsecureChannelProcessor();
        assertEquals("REQUIRES_INSECURE_CHANNEL", processor.getInsecureKeyword());
        processor.setInsecureKeyword("X");
        assertEquals("X", processor.getInsecureKeyword());

        assertTrue(processor.getEntryPoint() != null);
        processor.setEntryPoint(null);
        assertTrue(processor.getEntryPoint() == null);
    }

    public void testMissingEntryPoint() throws Exception {
        InsecureChannelProcessor processor = new InsecureChannelProcessor();
        processor.setEntryPoint(null);

        try {
            processor.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("entryPoint required", expected.getMessage());
        }
    }

    public void testMissingSecureChannelKeyword() throws Exception {
        InsecureChannelProcessor processor = new InsecureChannelProcessor();
        processor.setInsecureKeyword(null);

        try {
            processor.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("insecureKeyword required", expected.getMessage());
        }

        processor.setInsecureKeyword("");

        try {
            processor.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("insecureKeyword required", expected.getMessage());
        }
    }

    public void testSupports() {
        InsecureChannelProcessor processor = new InsecureChannelProcessor();
        assertTrue(processor.supports(
                new SecurityConfig("REQUIRES_INSECURE_CHANNEL")));
        assertFalse(processor.supports(null));
        assertFalse(processor.supports(new SecurityConfig("NOT_SUPPORTED")));
    }
}
