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

import junit.framework.TestCase;

import org.springframework.security.MockFilterConfig;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


/**
 * Tests {@link FilterToBeanProxy}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class FilterToBeanProxyTests extends TestCase {
    //~ Constructors ===================================================================================================

    public FilterToBeanProxyTests() {
        super();
    }

    public FilterToBeanProxyTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    private void executeFilterInContainerSimulator(FilterConfig filterConfig, Filter filter, ServletRequest request,
        ServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {
        filter.init(filterConfig);
        filter.doFilter(request, response, filterChain);
        filter.destroy();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(FilterToBeanProxyTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testDetectsClassNotInClassLoader() throws Exception {
        // Setup our filter
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("targetClass", "net.sf.DOES.NOT.EXIST");

        FilterToBeanProxy filter = new MockFilterToBeanProxy("org/springframework/security/util/filtertest-valid.xml");

        try {
            filter.init(config);
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertEquals("Class of type net.sf.DOES.NOT.EXIST not found in classloader", expected.getMessage());
        }
    }

    public void testDetectsNeitherPropertyBeingSet() throws Exception {
        // Setup our filter
        MockFilterConfig config = new MockFilterConfig();

        FilterToBeanProxy filter = new MockFilterToBeanProxy("org/springframework/security/util/filtertest-valid.xml");

        try {
            filter.init(config);
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertEquals("targetClass or targetBean must be specified", expected.getMessage());
        }
    }

    public void testDetectsTargetBeanIsNotAFilter() throws Exception {
        // Setup our filter
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("targetClass", "org.springframework.security.util.MockNotAFilter");

        FilterToBeanProxy filter = new MockFilterToBeanProxy("org/springframework/security/util/filtertest-valid.xml");

        try {
            filter.init(config);
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertEquals("Bean 'mockNotAFilter' does not implement javax.servlet.Filter", expected.getMessage());
        }
    }

    public void testDetectsTargetBeanNotInBeanContext()
        throws Exception {
        // Setup our filter
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("targetBean", "WRONG_NAME");

        FilterToBeanProxy filter = new MockFilterToBeanProxy("org/springframework/security/util/filtertest-valid.xml");

        try {
            filter.init(config);
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertEquals("targetBean 'WRONG_NAME' not found in context", expected.getMessage());
        }
    }

    public void testDetectsTargetClassNotInBeanContext()
        throws Exception {
        // Setup our filter
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("targetClass", "org.springframework.security.util.FilterToBeanProxyTests");

        FilterToBeanProxy filter = new MockFilterToBeanProxy("org/springframework/security/util/filtertest-valid.xml");

        try {
            filter.init(config);
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertEquals("Bean context must contain at least one bean of type org.springframework.security.util.FilterToBeanProxyTests",
                expected.getMessage());
        }
    }

    public void testIgnoresEmptyTargetBean() throws Exception {
        // Setup our filter
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("targetClass", "org.springframework.security.util.MockFilter");
        config.setInitParmeter("targetBean", "");

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockHttpServletRequest request = new MockHttpServletRequest();

        FilterToBeanProxy filter = new MockFilterToBeanProxy("org/springframework/security/util/filtertest-valid.xml");

        executeFilterInContainerSimulator(config, filter, request, response, chain);
    }

    public void testNormalOperationWithLazyTrue() throws Exception {
        // Setup our filter
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("targetBean", "mockFilter");
        config.setInitParmeter("init", "lazy");

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockHttpServletRequest request = new MockHttpServletRequest();

        FilterToBeanProxy filter = new MockFilterToBeanProxy("org/springframework/security/util/filtertest-valid.xml");

        executeFilterInContainerSimulator(config, filter, request, response, chain);
    }

    public void testNormalOperationWithSpecificBeanName()
        throws Exception {
        // Setup our filter
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("targetBean", "mockFilter");

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockHttpServletRequest request = new MockHttpServletRequest();

        FilterToBeanProxy filter = new MockFilterToBeanProxy("org/springframework/security/util/filtertest-valid.xml");

        executeFilterInContainerSimulator(config, filter, request, response, chain);
    }

    public void testNormalOperationWithTargetClass() throws Exception {
        // Setup our filter
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("targetClass", "org.springframework.security.util.MockFilter");

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockHttpServletRequest request = new MockHttpServletRequest();

        FilterToBeanProxy filter = new MockFilterToBeanProxy("org/springframework/security/util/filtertest-valid.xml");

        executeFilterInContainerSimulator(config, filter, request, response, chain);
    }

    public void testNullDelegateDoesNotCauseNullPointerException()
        throws Exception {
        // Setup our filter
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("targetBean", "aFilterThatDoesntExist");
        config.setInitParmeter("init", "lazy");

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockHttpServletRequest request = new MockHttpServletRequest();

        FilterToBeanProxy filter = new MockFilterToBeanProxy("org/springframework/security/util/filtertest-valid.xml");

        // do not init (which would hapen if called .doFilter)
        filter.destroy();
    }

    //~ Inner Classes ==================================================================================================

    private class MockFilterToBeanProxy extends FilterToBeanProxy {
        private String appContextLocation;

        public MockFilterToBeanProxy(String appContextLocation) {
            this.appContextLocation = appContextLocation;
        }

        private MockFilterToBeanProxy() {
            super();
        }

        protected ApplicationContext getContext(FilterConfig filterConfig) {
            return new ClassPathXmlApplicationContext(appContextLocation);
        }
    }
}
