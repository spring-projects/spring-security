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

package org.springframework.security.securechannel;

import junit.framework.TestCase;

import org.springframework.security.ConfigAttribute;
import org.springframework.security.SecurityConfig;

import org.springframework.security.intercept.web.FilterInvocation;
import org.springframework.security.intercept.web.FilterInvocationDefinitionSource;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;

import java.util.Collection;
import java.util.List;
import java.util.Vector;

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
    //~ Methods ========================================================================================================

    public void testDetectsMissingChannelDecisionManager()
        throws Exception {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();

        MockFilterInvocationDefinitionMap fids = new MockFilterInvocationDefinitionMap("/path", true, "MOCK");
        filter.setFilterInvocationDefinitionSource(fids);

        try {
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("channelDecisionManager must be specified", expected.getMessage());
        }
    }

    public void testDetectsMissingFilterInvocationDefinitionSource()
        throws Exception {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();
        filter.setChannelDecisionManager(new MockChannelDecisionManager(false, "MOCK"));

        try {
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("filterInvocationDefinitionSource must be specified", expected.getMessage());
        }
    }

    public void testDetectsSupportedConfigAttribute() throws Exception {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();
        filter.setChannelDecisionManager(new MockChannelDecisionManager(false, "SUPPORTS_MOCK_ONLY"));

        MockFilterInvocationDefinitionMap fids = new MockFilterInvocationDefinitionMap("/path", true, "SUPPORTS_MOCK_ONLY");

        filter.setFilterInvocationDefinitionSource(fids);

        filter.afterPropertiesSet();
        assertTrue(true);
    }

    public void testDetectsUnsupportedConfigAttribute() throws Exception {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();
        filter.setChannelDecisionManager(new MockChannelDecisionManager(false, "SUPPORTS_MOCK_ONLY"));

        MockFilterInvocationDefinitionMap fids = new MockFilterInvocationDefinitionMap("/path", true, "SUPPORTS_MOCK_ONLY", "INVALID_ATTRIBUTE");

        filter.setFilterInvocationDefinitionSource(fids);

        try {
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().startsWith("Unsupported configuration attributes:"));
        }
    }

    public void testDoFilterWhenManagerDoesCommitResponse() throws Exception {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();
        filter.setChannelDecisionManager(new MockChannelDecisionManager(true, "SOME_ATTRIBUTE"));

        MockFilterInvocationDefinitionMap fids = new MockFilterInvocationDefinitionMap("/path", true, "SOME_ATTRIBUTE");

        filter.setFilterInvocationDefinitionSource(fids);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setQueryString("info=now");
        request.setServletPath("/path");

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain(false);

        filter.doFilter(request, response, chain);
        assertTrue(true);
    }

    public void testDoFilterWhenManagerDoesNotCommitResponse() throws Exception {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();
        filter.setChannelDecisionManager(new MockChannelDecisionManager(false, "SOME_ATTRIBUTE"));

        MockFilterInvocationDefinitionMap fids = new MockFilterInvocationDefinitionMap("/path", true, "SOME_ATTRIBUTE");

        filter.setFilterInvocationDefinitionSource(fids);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setQueryString("info=now");
        request.setServletPath("/path");

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain(true);

        filter.doFilter(request, response, chain);
        assertTrue(true);
    }

    public void testDoFilterWhenNullConfigAttributeReturned()
        throws Exception {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();
        filter.setChannelDecisionManager(new MockChannelDecisionManager(false, "NOT_USED"));

        MockFilterInvocationDefinitionMap fids = new MockFilterInvocationDefinitionMap("/path", true, "NOT_USED");

        filter.setFilterInvocationDefinitionSource(fids);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setQueryString("info=now");
        request.setServletPath("/PATH_NOT_MATCHING_CONFIG_ATTRIBUTE");

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain(true);

        filter.doFilter(request, response, chain);
        assertTrue(true);
    }

    public void testDoFilterWithNonHttpServletRequestDetected() throws Exception {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();

        try {
            filter.doFilter(null, new MockHttpServletResponse(), new MockFilterChain());
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
        }
    }

    public void testDoFilterWithNonHttpServletResponseDetected() throws Exception {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();

        try {
            filter.doFilter(new MockHttpServletRequest(null, null), null, new MockFilterChain());
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
        }
    }

    public void testGetterSetters() throws Exception {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();
        filter.setChannelDecisionManager(new MockChannelDecisionManager(false, "MOCK"));
        assertTrue(filter.getChannelDecisionManager() != null);

        MockFilterInvocationDefinitionMap fids = new MockFilterInvocationDefinitionMap("/path", false, "MOCK");

        filter.setFilterInvocationDefinitionSource(fids);
        assertTrue(filter.getFilterInvocationDefinitionSource() != null);

        filter.init(null);
        filter.afterPropertiesSet();
        filter.destroy();
    }

    //~ Inner Classes ==================================================================================================

    private class MockChannelDecisionManager implements ChannelDecisionManager {
        private String supportAttribute;
        private boolean commitAResponse;

        public MockChannelDecisionManager(boolean commitAResponse, String supportAttribute) {
            this.commitAResponse = commitAResponse;
            this.supportAttribute = supportAttribute;
        }

        public void decide(FilterInvocation invocation, List<ConfigAttribute> config)
            throws IOException, ServletException {
            if (commitAResponse) {
                invocation.getHttpResponse().sendRedirect("/redirected");
            }
        }

        public boolean supports(ConfigAttribute attribute) {
            if (attribute.getAttribute().equals(supportAttribute)) {
                return true;
            } else {
                return false;
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

    private class MockFilterInvocationDefinitionMap implements FilterInvocationDefinitionSource {
        private List<ConfigAttribute> toReturn;
        private String servletPath;
        private boolean provideIterator;

        public MockFilterInvocationDefinitionMap(String servletPath, boolean provideIterator, String... toReturn) {
            this.servletPath = servletPath;
            this.toReturn = SecurityConfig.createList(toReturn);
            this.provideIterator = provideIterator;
        }

        public List<ConfigAttribute> getAttributes(Object object)
            throws IllegalArgumentException {
            FilterInvocation fi = (FilterInvocation) object;

            if (servletPath.equals(fi.getHttpRequest().getServletPath())) {
                return toReturn;
            } else {
                return null;
            }
        }

        public Collection<List<? extends ConfigAttribute>> getAllConfigAttributes() {
            if (!provideIterator) {
                return null;
            }

            List list = new Vector();
            list.add(toReturn);

            return list;
        }

        public boolean supports(Class clazz) {
            return true;
        }
    }
}
