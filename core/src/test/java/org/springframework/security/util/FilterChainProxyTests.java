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

package org.springframework.security.util;


import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.MockApplicationContext;
import org.springframework.security.MockFilterConfig;
import org.springframework.security.context.HttpSessionContextIntegrationFilter;
import org.springframework.security.intercept.web.MockFilterInvocationDefinitionSource;
import org.springframework.security.intercept.web.PathBasedFilterInvocationDefinitionMap;
import org.springframework.security.ui.webapp.AuthenticationProcessingFilter;

import java.util.List;

/**
 * Tests {@link FilterChainProxy}.
 *
 * @author Carlos Sanchez
 * @author Ben Alex
 * @version $Id$
 */
public class FilterChainProxyTests {
    private ClassPathXmlApplicationContext appCtx;

    //~ Methods ========================================================================================================

    @Before
    public void loadContext() {
        appCtx = new ClassPathXmlApplicationContext("org/springframework/security/util/filtertest-valid.xml");
    }

    @After
    public void closeContext() {
        if (appCtx != null) {
            appCtx.close();
        }
    }

    @Test
    public void testDetectsFilterInvocationDefinitionSourceThatDoesNotReturnAllConfigAttributes() throws Exception {
        FilterChainProxy filterChainProxy = new FilterChainProxy();
        filterChainProxy.setApplicationContext(MockApplicationContext.getContext());

        try {
            filterChainProxy.setFilterInvocationDefinitionSource(new MockFilterInvocationDefinitionSource(false, false));
            filterChainProxy.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("FilterChainProxy requires the FilterInvocationDefinitionSource to return a non-null response to getConfigAttributeDefinitions()",
                expected.getMessage());
        }
    }

    @Test
    public void testDetectsIfConfigAttributeDoesNotReturnValueForGetAttributeMethod() throws Exception {
        FilterChainProxy filterChainProxy = new FilterChainProxy();
        filterChainProxy.setApplicationContext(MockApplicationContext.getContext());

        ConfigAttributeDefinition cad = new ConfigAttributeDefinition();
        cad.addConfigAttribute(new MockConfigAttribute());

        PathBasedFilterInvocationDefinitionMap fids = new PathBasedFilterInvocationDefinitionMap();
        fids.addSecureUrl("/**", cad);

        filterChainProxy.setFilterInvocationDefinitionSource(fids);

        try {
            filterChainProxy.afterPropertiesSet();
            filterChainProxy.init(new MockFilterConfig());
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage()
                               .endsWith("returned null to the getAttribute() method, which is invalid when used with FilterChainProxy"));
        }
    }

    @Test
    public void testDetectsMissingFilterInvocationDefinitionSource() throws Exception {
        FilterChainProxy filterChainProxy = new FilterChainProxy();
        filterChainProxy.setApplicationContext(MockApplicationContext.getContext());

        try {
            filterChainProxy.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testDoNotFilter() throws Exception {
        FilterChainProxy filterChainProxy = (FilterChainProxy) appCtx.getBean("filterChain", FilterChainProxy.class);
        MockFilter filter = (MockFilter) appCtx.getBean("mockFilter", MockFilter.class);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/do/not/filter/somefile.html");

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain(true);

        filterChainProxy.doFilter(request, response, chain);
        assertFalse(filter.isWasInitialized());
        assertFalse(filter.isWasDoFiltered());
        assertFalse(filter.isWasDestroyed());
    }

    @Test
    public void misplacedUniversalPathShouldBeDetected() throws Exception {
        try {
            appCtx.getBean("newFilterChainProxyWrongPathOrder", FilterChainProxy.class);
            fail("Expected BeanCreationException");
        } catch (BeanCreationException expected) {
        }
    }

    @Test    
    public void normalOperation() throws Exception {
        FilterChainProxy filterChainProxy = (FilterChainProxy) appCtx.getBean("filterChain", FilterChainProxy.class);
        doNormalOperation(filterChainProxy);
    }

    @Test
    public void normalOperationWithNewConfig() throws Exception {
        FilterChainProxy filterChainProxy = (FilterChainProxy) appCtx.getBean("newFilterChainProxy", FilterChainProxy.class);
        checkPathAndFilterOrder(filterChainProxy);
        doNormalOperation(filterChainProxy);
    }

    @Test
    public void normalOperationWithNewConfigRegex() throws Exception {
        FilterChainProxy filterChainProxy = (FilterChainProxy) appCtx.getBean("newFilterChainProxyRegex", FilterChainProxy.class);
        checkPathAndFilterOrder(filterChainProxy);
        doNormalOperation(filterChainProxy);
    }

    @Test
    public void normalOperationWithNewConfigNonNamespace() throws Exception {
        FilterChainProxy filterChainProxy = (FilterChainProxy) appCtx.getBean("newFilterChainProxyNonNamespace", FilterChainProxy.class);
        checkPathAndFilterOrder(filterChainProxy);
        doNormalOperation(filterChainProxy);
    }

    private void checkPathAndFilterOrder(FilterChainProxy filterChainProxy) throws Exception {
        List filters = filterChainProxy.getFilters("/foo/blah");
        assertEquals(1, filters.size());
        assertTrue(filters.get(0) instanceof MockFilter);

        filters = filterChainProxy.getFilters("/some/other/path/blah");
        assertEquals(3, filters.size());
        assertTrue(filters.get(0) instanceof HttpSessionContextIntegrationFilter);
        assertTrue(filters.get(1) instanceof MockFilter);
        assertTrue(filters.get(2) instanceof MockFilter);

        filters = filterChainProxy.getFilters("/do/not/filter");
        assertEquals(0, filters.size());

        filters = filterChainProxy.getFilters("/another/nonspecificmatch");
        assertEquals(3, filters.size());
        assertTrue(filters.get(0) instanceof HttpSessionContextIntegrationFilter);
        assertTrue(filters.get(1) instanceof AuthenticationProcessingFilter);
        assertTrue(filters.get(2) instanceof MockFilter);
    }

    private void doNormalOperation(FilterChainProxy filterChainProxy) throws Exception {
        MockFilter filter = (MockFilter) appCtx.getBean("mockFilter", MockFilter.class);
        assertFalse(filter.isWasInitialized());
        assertFalse(filter.isWasDoFiltered());
        assertFalse(filter.isWasDestroyed());

        filterChainProxy.init(new MockFilterConfig());
        assertTrue(filter.isWasInitialized());
        assertFalse(filter.isWasDoFiltered());
        assertFalse(filter.isWasDestroyed());

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/foo/secure/super/somefile.html");

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain(true);

        filterChainProxy.doFilter(request, response, chain);
        assertTrue(filter.isWasInitialized());
        assertTrue(filter.isWasDoFiltered());
        assertFalse(filter.isWasDestroyed());

        request.setServletPath("/a/path/which/doesnt/match/any/filter.html");
        filterChainProxy.doFilter(request, response, chain);

        filterChainProxy.destroy();
        assertTrue(filter.isWasInitialized());
        assertTrue(filter.isWasDoFiltered());
        assertTrue(filter.isWasDestroyed());
    }

    //~ Inner Classes ==================================================================================================

    private class MockConfigAttribute implements ConfigAttribute {
        public String getAttribute() {
            return null;
        }
    }
}
