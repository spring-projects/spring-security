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

import net.sf.acegisecurity.ConfigAttributeDefinition;
import net.sf.acegisecurity.MockFilterChain;
import net.sf.acegisecurity.MockHttpServletRequest;
import net.sf.acegisecurity.MockHttpServletResponse;
import net.sf.acegisecurity.SecurityConfig;
import net.sf.acegisecurity.intercept.web.FilterInvocation;


/**
 * Tests {@link ChannelDecisionManagerImpl}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ChannelDecisionManagerImplTests extends TestCase {
    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(ChannelDecisionManagerImplTests.class);
    }

    public void testDetectsInvalidInsecureKeyword() throws Exception {
        ChannelDecisionManagerImpl cdm = new ChannelDecisionManagerImpl();
        cdm.setInsecureKeyword("");

        try {
            cdm.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("insecureKeyword required", expected.getMessage());
        }

        cdm.setInsecureKeyword(null);

        try {
            cdm.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("insecureKeyword required", expected.getMessage());
        }
    }

    public void testDetectsInvalidSecureKeyword() throws Exception {
        ChannelDecisionManagerImpl cdm = new ChannelDecisionManagerImpl();
        cdm.setSecureKeyword("");

        try {
            cdm.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("secureKeyword required", expected.getMessage());
        }

        cdm.setSecureKeyword(null);

        try {
            cdm.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("secureKeyword required", expected.getMessage());
        }
    }

    public void testDetectsNullsPassedToMainMethod() {
        ChannelDecisionManagerImpl cdm = new ChannelDecisionManagerImpl();

        try {
            cdm.decide(null, new ConfigAttributeDefinition());
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("Nulls cannot be provided", expected.getMessage());
        }

        try {
            cdm.decide(new FilterInvocation(new MockHttpServletRequest("x"),
                    new MockHttpServletResponse(), new MockFilterChain()), null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("Nulls cannot be provided", expected.getMessage());
        }
    }

    public void testDetectsWhenInsecureChannelNeededAndInsecureSchemeUsed() {
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition();
        attr.addConfigAttribute(new SecurityConfig(
                "SOME_CONFIG_ATTRIBUTE_TO_IGNORE"));
        attr.addConfigAttribute(new SecurityConfig("REQUIRES_INSECURE_CHANNEL"));

        MockHttpServletRequest request = new MockHttpServletRequest("foo=bar");
        request.setScheme("http");

        ChannelDecisionManagerImpl cdm = new ChannelDecisionManagerImpl();
        cdm.decide(new FilterInvocation(request, new MockHttpServletResponse(),
                new MockFilterChain()), attr);
        assertTrue(true);
    }

    public void testDetectsWhenInsecureChannelNeededAndSecureSchemeUsed() {
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition();
        attr.addConfigAttribute(new SecurityConfig(
                "SOME_CONFIG_ATTRIBUTE_TO_IGNORE"));
        attr.addConfigAttribute(new SecurityConfig("REQUIRES_INSECURE_CHANNEL"));

        MockHttpServletRequest request = new MockHttpServletRequest("foo=bar");
        request.setScheme("https");

        ChannelDecisionManagerImpl cdm = new ChannelDecisionManagerImpl();

        try {
            cdm.decide(new FilterInvocation(request,
                    new MockHttpServletResponse(), new MockFilterChain()), attr);
        } catch (InsecureChannelRequiredException expected) {
            assertTrue(true);
        }
    }

    public void testDetectsWhenSecureChannelNeeded() {
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition();
        attr.addConfigAttribute(new SecurityConfig(
                "SOME_CONFIG_ATTRIBUTE_TO_IGNORE"));
        attr.addConfigAttribute(new SecurityConfig("REQUIRES_SECURE_CHANNEL"));

        MockHttpServletRequest request = new MockHttpServletRequest("foo=bar");
        request.setScheme("http");

        ChannelDecisionManagerImpl cdm = new ChannelDecisionManagerImpl();

        try {
            cdm.decide(new FilterInvocation(request,
                    new MockHttpServletResponse(), new MockFilterChain()), attr);
        } catch (SecureChannelRequiredException expected) {
            assertTrue(true);
        }
    }

    public void testGetterSetters() throws Exception {
        ChannelDecisionManagerImpl cdm = new ChannelDecisionManagerImpl();
        cdm.afterPropertiesSet();
        assertEquals("REQUIRES_INSECURE_CHANNEL", cdm.getInsecureKeyword());
        assertEquals("REQUIRES_SECURE_CHANNEL", cdm.getSecureKeyword());

        cdm.setInsecureKeyword("MY_INSECURE");
        cdm.setSecureKeyword("MY_SECURE");

        assertEquals("MY_INSECURE", cdm.getInsecureKeyword());
        assertEquals("MY_SECURE", cdm.getSecureKeyword());
    }

    public void testIgnoresOtherConfigAttributes() {
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition();
        attr.addConfigAttribute(new SecurityConfig("XYZ"));

        ChannelDecisionManagerImpl cdm = new ChannelDecisionManagerImpl();
        cdm.decide(new FilterInvocation(new MockHttpServletRequest("x"),
                new MockHttpServletResponse(), new MockFilterChain()), attr);
        assertTrue(true);
    }
}
;
