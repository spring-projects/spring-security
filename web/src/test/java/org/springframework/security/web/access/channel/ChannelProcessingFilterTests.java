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

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.util.Collection;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;


/**
 * Tests {@link ChannelProcessingFilter}.
 *
 * @author Ben Alex
 */
public class ChannelProcessingFilterTests {
    //~ Methods ========================================================================================================

    @Test(expected=IllegalArgumentException.class)
    public void testDetectsMissingChannelDecisionManager() throws Exception {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();

        MockFilterInvocationDefinitionMap fids = new MockFilterInvocationDefinitionMap("/path", true, "MOCK");
        filter.setSecurityMetadataSource(fids);

        filter.afterPropertiesSet();
    }

    @Test(expected=IllegalArgumentException.class)
    public void testDetectsMissingFilterInvocationSecurityMetadataSource() throws Exception {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();
        filter.setChannelDecisionManager(new MockChannelDecisionManager(false, "MOCK"));
        filter.afterPropertiesSet();
    }

    @Test
    public void testDetectsSupportedConfigAttribute() throws Exception {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();
        filter.setChannelDecisionManager(new MockChannelDecisionManager(false, "SUPPORTS_MOCK_ONLY"));

        MockFilterInvocationDefinitionMap fids = new MockFilterInvocationDefinitionMap("/path", true, "SUPPORTS_MOCK_ONLY");

        filter.setSecurityMetadataSource(fids);

        filter.afterPropertiesSet();
    }

    @Test(expected=IllegalArgumentException.class)
    public void testDetectsUnsupportedConfigAttribute() throws Exception {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();
        filter.setChannelDecisionManager(new MockChannelDecisionManager(false, "SUPPORTS_MOCK_ONLY"));

        MockFilterInvocationDefinitionMap fids = new MockFilterInvocationDefinitionMap("/path", true, "SUPPORTS_MOCK_ONLY", "INVALID_ATTRIBUTE");

        filter.setSecurityMetadataSource(fids);
        filter.afterPropertiesSet();
    }

    @Test
    public void testDoFilterWhenManagerDoesCommitResponse() throws Exception {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();
        filter.setChannelDecisionManager(new MockChannelDecisionManager(true, "SOME_ATTRIBUTE"));

        MockFilterInvocationDefinitionMap fids = new MockFilterInvocationDefinitionMap("/path", true, "SOME_ATTRIBUTE");

        filter.setSecurityMetadataSource(fids);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setQueryString("info=now");
        request.setServletPath("/path");

        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mock(FilterChain.class));
    }

    @Test
    public void testDoFilterWhenManagerDoesNotCommitResponse() throws Exception {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();
        filter.setChannelDecisionManager(new MockChannelDecisionManager(false, "SOME_ATTRIBUTE"));

        MockFilterInvocationDefinitionMap fids = new MockFilterInvocationDefinitionMap("/path", true, "SOME_ATTRIBUTE");

        filter.setSecurityMetadataSource(fids);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setQueryString("info=now");
        request.setServletPath("/path");

        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mock(FilterChain.class));
    }

    @Test
    public void testDoFilterWhenNullConfigAttributeReturned() throws Exception {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();
        filter.setChannelDecisionManager(new MockChannelDecisionManager(false, "NOT_USED"));

        MockFilterInvocationDefinitionMap fids = new MockFilterInvocationDefinitionMap("/path", true, "NOT_USED");

        filter.setSecurityMetadataSource(fids);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setQueryString("info=now");
        request.setServletPath("/PATH_NOT_MATCHING_CONFIG_ATTRIBUTE");

        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mock(FilterChain.class));
    }

    @Test
    public void testGetterSetters() throws Exception {
        ChannelProcessingFilter filter = new ChannelProcessingFilter();
        filter.setChannelDecisionManager(new MockChannelDecisionManager(false, "MOCK"));
        assertTrue(filter.getChannelDecisionManager() != null);

        MockFilterInvocationDefinitionMap fids = new MockFilterInvocationDefinitionMap("/path", false, "MOCK");

        filter.setSecurityMetadataSource(fids);
        assertSame(fids, filter.getSecurityMetadataSource());

        filter.afterPropertiesSet();
    }

    //~ Inner Classes ==================================================================================================

    private class MockChannelDecisionManager implements ChannelDecisionManager {
        private String supportAttribute;
        private boolean commitAResponse;

        public MockChannelDecisionManager(boolean commitAResponse, String supportAttribute) {
            this.commitAResponse = commitAResponse;
            this.supportAttribute = supportAttribute;
        }

        public void decide(FilterInvocation invocation, Collection<ConfigAttribute> config)
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

    private class MockFilterInvocationDefinitionMap implements FilterInvocationSecurityMetadataSource {
        private Collection<ConfigAttribute> toReturn;
        private String servletPath;
        private boolean provideIterator;

        public MockFilterInvocationDefinitionMap(String servletPath, boolean provideIterator, String... toReturn) {
            this.servletPath = servletPath;
            this.toReturn = SecurityConfig.createList(toReturn);
            this.provideIterator = provideIterator;
        }

        public Collection<ConfigAttribute> getAttributes(Object object)
            throws IllegalArgumentException {
            FilterInvocation fi = (FilterInvocation) object;

            if (servletPath.equals(fi.getHttpRequest().getServletPath())) {
                return toReturn;
            } else {
                return null;
            }
        }

        public Collection<ConfigAttribute> getAllConfigAttributes() {
            if (!provideIterator) {
                return null;
            }

            return toReturn;
        }

        public boolean supports(Class<?> clazz) {
            return true;
        }
    }
}
