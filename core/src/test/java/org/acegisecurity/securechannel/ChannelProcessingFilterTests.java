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
import net.sf.acegisecurity.MockFilterConfig;
import net.sf.acegisecurity.MockHttpServletRequest;
import net.sf.acegisecurity.MockHttpServletResponse;
import net.sf.acegisecurity.SecurityConfig;
import net.sf.acegisecurity.intercept.web.FilterInvocation;
import net.sf.acegisecurity.intercept.web.FilterInvocationDefinitionSource;
import net.sf.acegisecurity.intercept.web.RegExpBasedFilterInvocationDefinitionMap;

import java.io.IOException;

import java.util.Iterator;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


/**
 * Tests {@link ChannelProcessingFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ChannelProcessingFilterTests extends TestCase {
    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(ChannelProcessingFilterTests.class);
    }

    public void testCallsInsecureEntryPointWhenTooMuchChannelSecurity()
        throws Exception {
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition();
        attr.addConfigAttribute(new SecurityConfig("REQUIRES_INSECURE_CHANNEL"));

        MockFilterInvocationDefinitionMap fids = new MockFilterInvocationDefinitionMap("/path",
                attr);

        ChannelProcessingFilter filter = new ChannelProcessingFilter();
        filter.setInsecureChannelEntryPoint(new MockEntryPoint(true));
        filter.setSecureChannelEntryPoint(new MockEntryPoint(false));
        filter.setFilterInvocationDefinitionSource(fids);
        filter.setChannelDecisionManager(new ChannelDecisionManagerImpl());

        MockHttpServletRequest request = new MockHttpServletRequest("info=now");
        request.setServletPath("/path");
        request.setScheme("https");

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain(false);

        filter.doFilter(request, response, chain);
        assertTrue(true);
    }

    public void testCallsSecureEntryPointWhenTooLittleChannelSecurity()
        throws Exception {
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition();
        attr.addConfigAttribute(new SecurityConfig("REQUIRES_SECURE_CHANNEL"));

        MockFilterInvocationDefinitionMap fids = new MockFilterInvocationDefinitionMap("/path",
                attr);

        ChannelProcessingFilter filter = new ChannelProcessingFilter();
        filter.setInsecureChannelEntryPoint(new MockEntryPoint(false));
        filter.setSecureChannelEntryPoint(new MockEntryPoint(true));
        filter.setFilterInvocationDefinitionSource(fids);
        filter.setChannelDecisionManager(new ChannelDecisionManagerImpl());

        MockHttpServletRequest request = new MockHttpServletRequest("info=now");
        request.setServletPath("/path");
        request.setScheme("http");

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain(false);

        filter.doFilter(request, response, chain);
        assertTrue(true);
    }

    public void testDetectsMissingChannelDecisionManager()
        throws Exception {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();
        filter.setSecureChannelEntryPoint(new RetryWithHttpsEntryPoint());
        filter.setFilterInvocationDefinitionSource(new RegExpBasedFilterInvocationDefinitionMap());

        try {
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("channelDecisionManager must be specified",
                expected.getMessage());
        }
    }

    public void testDetectsMissingFilterInvocationDefinitionMap()
        throws Exception {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();
        filter.setInsecureChannelEntryPoint(new RetryWithHttpEntryPoint());
        filter.setSecureChannelEntryPoint(new RetryWithHttpsEntryPoint());
        filter.setChannelDecisionManager(new ChannelDecisionManagerImpl());

        try {
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("filterInvocationDefinitionSource must be specified",
                expected.getMessage());
        }
    }

    public void testDetectsMissingInsecureChannelEntryPoint()
        throws Exception {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();
        filter.setSecureChannelEntryPoint(new RetryWithHttpsEntryPoint());
        filter.setFilterInvocationDefinitionSource(new RegExpBasedFilterInvocationDefinitionMap());
        filter.setChannelDecisionManager(new ChannelDecisionManagerImpl());

        try {
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("insecureChannelEntryPoint must be specified",
                expected.getMessage());
        }
    }

    public void testDetectsMissingSecureChannelEntryPoint()
        throws Exception {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();
        filter.setInsecureChannelEntryPoint(new RetryWithHttpEntryPoint());
        filter.setFilterInvocationDefinitionSource(new RegExpBasedFilterInvocationDefinitionMap());
        filter.setChannelDecisionManager(new ChannelDecisionManagerImpl());

        try {
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("secureChannelEntryPoint must be specified",
                expected.getMessage());
        }
    }

    public void testDoFilterWithNonHttpServletRequestDetected()
        throws Exception {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();

        try {
            filter.doFilter(null, new MockHttpServletResponse(),
                new MockFilterChain());
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertEquals("HttpServletRequest required", expected.getMessage());
        }
    }

    public void testDoFilterWithNonHttpServletResponseDetected()
        throws Exception {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();

        try {
            filter.doFilter(new MockHttpServletRequest(null, null), null,
                new MockFilterChain());
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertEquals("HttpServletResponse required", expected.getMessage());
        }
    }

    public void testDoesNotInterruptRequestsWithCorrectChannelSecurity()
        throws Exception {
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition();
        attr.addConfigAttribute(new SecurityConfig("REQUIRES_SECURE_CHANNEL"));

        MockFilterInvocationDefinitionMap fids = new MockFilterInvocationDefinitionMap("/path",
                attr);

        ChannelProcessingFilter filter = new ChannelProcessingFilter();
        filter.setInsecureChannelEntryPoint(new RetryWithHttpEntryPoint());
        filter.setSecureChannelEntryPoint(new RetryWithHttpsEntryPoint());
        filter.setFilterInvocationDefinitionSource(fids);
        filter.setChannelDecisionManager(new ChannelDecisionManagerImpl());

        MockHttpServletRequest request = new MockHttpServletRequest("info=now");
        request.setServletPath("/path");
        request.setScheme("https");

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain(true);

        filter.doFilter(request, response, chain);
        assertTrue(true);
    }

    public void testDoesNotInterruptRequestsWithNoConfigAttribute()
        throws Exception {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();
        filter.setInsecureChannelEntryPoint(new RetryWithHttpEntryPoint());
        filter.setSecureChannelEntryPoint(new RetryWithHttpsEntryPoint());
        filter.setFilterInvocationDefinitionSource(new RegExpBasedFilterInvocationDefinitionMap());
        filter.setChannelDecisionManager(new ChannelDecisionManagerImpl());

        MockHttpServletRequest request = new MockHttpServletRequest("info=now");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain(true);

        filter.doFilter(request, response, chain);
        assertTrue(true);
    }

    public void testGetterSetters() {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();
        filter.setInsecureChannelEntryPoint(new RetryWithHttpEntryPoint());
        filter.setSecureChannelEntryPoint(new RetryWithHttpsEntryPoint());
        filter.setFilterInvocationDefinitionSource(new RegExpBasedFilterInvocationDefinitionMap());
        filter.setChannelDecisionManager(new ChannelDecisionManagerImpl());

        assertTrue(filter.getInsecureChannelEntryPoint() != null);
        assertTrue(filter.getSecureChannelEntryPoint() != null);
        assertTrue(filter.getFilterInvocationDefinitionSource() != null);
        assertTrue(filter.getChannelDecisionManager() != null);
    }

    public void testLifecycle() throws Exception {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();
        filter.setInsecureChannelEntryPoint(new RetryWithHttpEntryPoint());
        filter.setSecureChannelEntryPoint(new RetryWithHttpsEntryPoint());
        filter.setFilterInvocationDefinitionSource(new RegExpBasedFilterInvocationDefinitionMap());
        filter.setChannelDecisionManager(new ChannelDecisionManagerImpl());
        filter.afterPropertiesSet();

        filter.init(new MockFilterConfig());
        filter.destroy();
    }

    //~ Inner Classes ==========================================================

    private class MockEntryPoint implements ChannelEntryPoint {
        private boolean expectToBeCalled;

        public MockEntryPoint(boolean expectToBeCalled) {
            this.expectToBeCalled = expectToBeCalled;
        }

        private MockEntryPoint() {
            super();
        }

        public void commence(ServletRequest request, ServletResponse response)
            throws IOException, ServletException {
            if (expectToBeCalled) {
                assertTrue(true);
            } else {
                fail("Did not expect this ChannelEntryPoint to be called");
            }
        }
    }

    private class MockFilterChain implements FilterChain {
        private boolean expectToProceed;

        public MockFilterChain(boolean expectToProceed) {
            this.expectToProceed = expectToProceed;
        }

        private MockFilterChain() {
            super();
        }

        public void doFilter(ServletRequest request, ServletResponse response)
            throws IOException, ServletException {
            if (expectToProceed) {
                assertTrue(true);
            } else {
                fail("Did not expect filter chain to proceed");
            }
        }
    }

    private class MockFilterInvocationDefinitionMap
        implements FilterInvocationDefinitionSource {
        private ConfigAttributeDefinition toReturn;
        private String servletPath;

        public MockFilterInvocationDefinitionMap(String servletPath,
            ConfigAttributeDefinition toReturn) {
            this.servletPath = servletPath;
            this.toReturn = toReturn;
        }

        private MockFilterInvocationDefinitionMap() {
            super();
        }

        public ConfigAttributeDefinition getAttributes(Object object)
            throws IllegalArgumentException {
            FilterInvocation fi = (FilterInvocation) object;

            if (servletPath.equals(fi.getHttpRequest().getServletPath())) {
                return toReturn;
            } else {
                return null;
            }
        }

        public Iterator getConfigAttributeDefinitions() {
            return null;
        }

        public boolean supports(Class clazz) {
            return true;
        }
    }
}
