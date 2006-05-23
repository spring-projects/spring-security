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

package org.acegisecurity.securechannel;

import junit.framework.TestCase;

import org.acegisecurity.ConfigAttribute;
import org.acegisecurity.ConfigAttributeDefinition;
import org.acegisecurity.MockFilterChain;
import org.acegisecurity.SecurityConfig;

import org.acegisecurity.intercept.web.FilterInvocation;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;

import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import javax.servlet.ServletException;


/**
 * Tests {@link ChannelDecisionManagerImpl}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ChannelDecisionManagerImplTests extends TestCase {
    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(ChannelDecisionManagerImplTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testCannotSetEmptyChannelProcessorsList()
        throws Exception {
        ChannelDecisionManagerImpl cdm = new ChannelDecisionManagerImpl();

        try {
            cdm.setChannelProcessors(new Vector());
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("A list of ChannelProcessors is required", expected.getMessage());
        }
    }

    public void testCannotSetIncorrectObjectTypesIntoChannelProcessorsList()
        throws Exception {
        ChannelDecisionManagerImpl cdm = new ChannelDecisionManagerImpl();
        List list = new Vector();
        list.add("THIS IS NOT A CHANNELPROCESSOR");

        try {
            cdm.setChannelProcessors(list);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testCannotSetNullChannelProcessorsList()
        throws Exception {
        ChannelDecisionManagerImpl cdm = new ChannelDecisionManagerImpl();

        try {
            cdm.setChannelProcessors(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("A list of ChannelProcessors is required", expected.getMessage());
        }
    }

    public void testDecideIsOperational() throws Exception {
        ChannelDecisionManagerImpl cdm = new ChannelDecisionManagerImpl();
        MockChannelProcessor cpXyz = new MockChannelProcessor("xyz", false);
        MockChannelProcessor cpAbc = new MockChannelProcessor("abc", true);
        List list = new Vector();
        list.add(cpXyz);
        list.add(cpAbc);
        cdm.setChannelProcessors(list);
        cdm.afterPropertiesSet();

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        FilterInvocation fi = new FilterInvocation(request, response, chain);

        ConfigAttributeDefinition cad = new ConfigAttributeDefinition();
        cad.addConfigAttribute(new SecurityConfig("xyz"));

        cdm.decide(fi, cad);
        assertTrue(fi.getResponse().isCommitted());
    }

    public void testDecideIteratesAllProcessorsIfNoneCommitAResponse()
        throws Exception {
        ChannelDecisionManagerImpl cdm = new ChannelDecisionManagerImpl();
        MockChannelProcessor cpXyz = new MockChannelProcessor("xyz", false);
        MockChannelProcessor cpAbc = new MockChannelProcessor("abc", false);
        List list = new Vector();
        list.add(cpXyz);
        list.add(cpAbc);
        cdm.setChannelProcessors(list);
        cdm.afterPropertiesSet();

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        FilterInvocation fi = new FilterInvocation(request, response, chain);

        ConfigAttributeDefinition cad = new ConfigAttributeDefinition();
        cad.addConfigAttribute(new SecurityConfig("SOME_ATTRIBUTE_NO_PROCESSORS_SUPPORT"));

        cdm.decide(fi, cad);
        assertFalse(fi.getResponse().isCommitted());
    }

    public void testDelegatesSupports() throws Exception {
        ChannelDecisionManagerImpl cdm = new ChannelDecisionManagerImpl();
        MockChannelProcessor cpXyz = new MockChannelProcessor("xyz", false);
        MockChannelProcessor cpAbc = new MockChannelProcessor("abc", false);
        List list = new Vector();
        list.add(cpXyz);
        list.add(cpAbc);
        cdm.setChannelProcessors(list);
        cdm.afterPropertiesSet();

        assertTrue(cdm.supports(new SecurityConfig("xyz")));
        assertTrue(cdm.supports(new SecurityConfig("abc")));
        assertFalse(cdm.supports(new SecurityConfig("UNSUPPORTED")));
    }

    public void testGettersSetters() {
        ChannelDecisionManagerImpl cdm = new ChannelDecisionManagerImpl();
        assertNull(cdm.getChannelProcessors());

        MockChannelProcessor cpXyz = new MockChannelProcessor("xyz", false);
        MockChannelProcessor cpAbc = new MockChannelProcessor("abc", false);
        List list = new Vector();
        list.add(cpXyz);
        list.add(cpAbc);
        cdm.setChannelProcessors(list);

        assertEquals(list, cdm.getChannelProcessors());
    }

    public void testStartupFailsWithEmptyChannelProcessorsList()
        throws Exception {
        ChannelDecisionManagerImpl cdm = new ChannelDecisionManagerImpl();

        try {
            cdm.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("A list of ChannelProcessors is required", expected.getMessage());
        }
    }

    //~ Inner Classes ==================================================================================================

    private class MockChannelProcessor implements ChannelProcessor {
        private String configAttribute;
        private boolean failIfCalled;

        public MockChannelProcessor(String configAttribute, boolean failIfCalled) {
            this.configAttribute = configAttribute;
            this.failIfCalled = failIfCalled;
        }

        private MockChannelProcessor() {
            super();
        }

        public void decide(FilterInvocation invocation, ConfigAttributeDefinition config)
            throws IOException, ServletException {
            Iterator iter = config.getConfigAttributes();

            if (failIfCalled) {
                fail("Should not have called this channel processor");
            }

            while (iter.hasNext()) {
                ConfigAttribute attr = (ConfigAttribute) iter.next();

                if (attr.equals(configAttribute)) {
                    invocation.getHttpResponse().sendRedirect("/redirected");

                    return;
                }
            }
        }

        public boolean supports(ConfigAttribute attribute) {
            if (attribute.getAttribute().equals(configAttribute)) {
                return true;
            } else {
                return false;
            }
        }
    }
}
