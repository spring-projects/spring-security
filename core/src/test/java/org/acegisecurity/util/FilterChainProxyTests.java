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

package net.sf.acegisecurity.util;

import junit.framework.TestCase;

import net.sf.acegisecurity.ConfigAttribute;
import net.sf.acegisecurity.ConfigAttributeDefinition;
import net.sf.acegisecurity.MockApplicationContext;
import net.sf.acegisecurity.MockFilterConfig;
import net.sf.acegisecurity.intercept.web.FilterInvocationDefinitionSource;
import net.sf.acegisecurity.intercept.web.MockFilterInvocationDefinitionSource;
import net.sf.acegisecurity.intercept.web.PathBasedFilterInvocationDefinitionMap;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;


/**
 * Tests {@link FilterChainProxy}.
 *
 * @author Carlos Sanchez
 * @author Ben Alex
 * @version $Id$
 */
public class FilterChainProxyTests extends TestCase {
    //~ Constructors ===========================================================

    // ===========================================================
    public FilterChainProxyTests() {
        super();
    }

    public FilterChainProxyTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    // ================================================================
    public static void main(String[] args) {
        junit.textui.TestRunner.run(FilterChainProxyTests.class);
    }

    public void testDetectsFilterInvocationDefinitionSourceThatDoesNotReturnAllConfigAttributes()
        throws Exception {
        FilterChainProxy filterChainProxy = new FilterChainProxy();
        filterChainProxy.setApplicationContext(MockApplicationContext
            .getContext());
        filterChainProxy.setFilterInvocationDefinitionSource(new MockFilterInvocationDefinitionSource(
                false, false));

        try {
            filterChainProxy.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("FilterChainProxy requires the FitlerInvocationDefinitionSource to return a non-null response to getConfigAttributeDefinitions()",
                expected.getMessage());
        }
    }

    public void testDetectsIfConfigAttributeDoesNotReturnValueForGetAttributeMethod()
        throws Exception {
        FilterChainProxy filterChainProxy = new FilterChainProxy();
        filterChainProxy.setApplicationContext(MockApplicationContext
            .getContext());

        ConfigAttributeDefinition cad = new ConfigAttributeDefinition();
        cad.addConfigAttribute(new MockConfigAttribute());

        PathBasedFilterInvocationDefinitionMap fids = new PathBasedFilterInvocationDefinitionMap();
        fids.addSecureUrl("/**", cad);

        filterChainProxy.setFilterInvocationDefinitionSource(fids);
        filterChainProxy.afterPropertiesSet();

        try {
            filterChainProxy.init(new MockFilterConfig());
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().endsWith("returned null to the getAttribute() method, which is invalid when used with FilterChainProxy"));
        }
    }

    public void testDetectsMissingFilterInvocationDefinitionSource()
        throws Exception {
        FilterChainProxy filterChainProxy = new FilterChainProxy();
        filterChainProxy.setApplicationContext(MockApplicationContext
            .getContext());

        try {
            filterChainProxy.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("filterInvocationDefinitionSource must be specified",
                expected.getMessage());
        }
    }

    public void testGettersSetters() {
        FilterChainProxy filterChainProxy = new FilterChainProxy();
        FilterInvocationDefinitionSource fids = new MockFilterInvocationDefinitionSource(false,
                false);
        filterChainProxy.setFilterInvocationDefinitionSource(fids);
        assertEquals(fids,
            filterChainProxy.getFilterInvocationDefinitionSource());
    }

    public void testNormalOperation() throws Exception {
        ApplicationContext appCtx = new ClassPathXmlApplicationContext(
                "net/sf/acegisecurity/util/filtertest-valid.xml");
        FilterChainProxy filterChainProxy = (FilterChainProxy) appCtx.getBean("filterChain",
                FilterChainProxy.class);
        MockFilter filter = (MockFilter) appCtx.getBean("mockFilter",
                MockFilter.class);
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

    //~ Inner Classes ==========================================================

    private class MockConfigAttribute implements ConfigAttribute {
        public String getAttribute() {
            return null;
        }
    }
}
