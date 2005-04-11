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

package net.sf.acegisecurity.intercept.web;

import junit.framework.TestCase;

import net.sf.acegisecurity.AccessDecisionManager;
import net.sf.acegisecurity.AccessDeniedException;
import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.ConfigAttribute;
import net.sf.acegisecurity.ConfigAttributeDefinition;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.MockAccessDecisionManager;
import net.sf.acegisecurity.MockApplicationContext;
import net.sf.acegisecurity.MockAuthenticationManager;
import net.sf.acegisecurity.MockRunAsManager;
import net.sf.acegisecurity.RunAsManager;
import net.sf.acegisecurity.SecurityConfig;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.security.SecureContext;
import net.sf.acegisecurity.context.security.SecureContextImpl;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import java.io.IOException;

import java.util.Iterator;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpServletRequest;


/**
 * Tests {@link FilterSecurityInterceptor}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class FilterSecurityInterceptorTests extends TestCase {
    //~ Constructors ===========================================================

    public FilterSecurityInterceptorTests() {
        super();
    }

    public FilterSecurityInterceptorTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(FilterSecurityInterceptorTests.class);
    }

    public void testEnsuresAccessDecisionManagerSupportsFilterInvocationClass()
        throws Exception {
        FilterSecurityInterceptor interceptor = new FilterSecurityInterceptor();
        interceptor.setAuthenticationManager(new MockAuthenticationManager());
        interceptor.setObjectDefinitionSource(new RegExpBasedFilterInvocationDefinitionMap());
        interceptor.setRunAsManager(new MockRunAsManager());

        interceptor.setAccessDecisionManager(new AccessDecisionManager() {
                public boolean supports(Class clazz) {
                    return false;
                }

                public boolean supports(ConfigAttribute attribute) {
                    return true;
                }

                public void decide(Authentication authentication,
                    Object object, ConfigAttributeDefinition config)
                    throws AccessDeniedException {
                    throw new UnsupportedOperationException(
                        "mock method not implemented");
                }
            });

        try {
            interceptor.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("AccessDecisionManager does not support secure object class: class net.sf.acegisecurity.intercept.web.FilterInvocation",
                expected.getMessage());
        }
    }

    public void testEnsuresRunAsManagerSupportsFilterInvocationClass()
        throws Exception {
        FilterSecurityInterceptor interceptor = new FilterSecurityInterceptor();
        interceptor.setAccessDecisionManager(new MockAccessDecisionManager());
        interceptor.setAuthenticationManager(new MockAuthenticationManager());
        interceptor.setObjectDefinitionSource(new RegExpBasedFilterInvocationDefinitionMap());

        interceptor.setRunAsManager(new RunAsManager() {
                public boolean supports(Class clazz) {
                    return false;
                }

                public boolean supports(ConfigAttribute attribute) {
                    return true;
                }

                public Authentication buildRunAs(
                    Authentication authentication, Object object,
                    ConfigAttributeDefinition config) {
                    throw new UnsupportedOperationException(
                        "mock method not implemented");
                }
            });

        try {
            interceptor.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("RunAsManager does not support secure object class: class net.sf.acegisecurity.intercept.web.FilterInvocation",
                expected.getMessage());
        }
    }

    public void testHttpsInvocationReflectsPortNumber()
        throws Throwable {
        // Setup the FilterSecurityInterceptor
        FilterSecurityInterceptor interceptor = new FilterSecurityInterceptor();
        interceptor.setAccessDecisionManager(new MockAccessDecisionManager());
        interceptor.setAuthenticationManager(new MockAuthenticationManager());
        interceptor.setRunAsManager(new MockRunAsManager());
        interceptor.setApplicationContext(MockApplicationContext.getContext());

        // Setup a mock config attribute definition
        ConfigAttributeDefinition def = new ConfigAttributeDefinition();
        def.addConfigAttribute(new SecurityConfig("MOCK_OK"));

        MockFilterInvocationDefinitionMap mockSource = new MockFilterInvocationDefinitionMap("/secure/page.html",
                def);
        interceptor.setObjectDefinitionSource(mockSource);

        // Setup our expectation that the filter chain will be invoked, as access is granted
        MockFilterChain chain = new MockFilterChain(true);

        // Setup our HTTPS request and response
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/secure/page.html");
        request.setScheme("https");
        request.setServerPort(443);

        // Setup a Context
        SecureContext context = new SecureContextImpl();
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test",
                "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("MOCK_OK")});
        context.setAuthentication(token);
        ContextHolder.setContext(context);

        // Create and test our secure object
        FilterInvocation fi = new FilterInvocation(request, response, chain);
        interceptor.invoke(fi);

        // Destroy the Context
        ContextHolder.setContext(null);
    }

    public void testNormalStartupAndGetter() throws Exception {
        FilterSecurityInterceptor interceptor = new FilterSecurityInterceptor();
        interceptor.setAccessDecisionManager(new MockAccessDecisionManager());
        interceptor.setAuthenticationManager(new MockAuthenticationManager());

        RegExpBasedFilterInvocationDefinitionMap fidp = new RegExpBasedFilterInvocationDefinitionMap();
        interceptor.setObjectDefinitionSource(fidp);
        interceptor.setRunAsManager(new MockRunAsManager());
        interceptor.afterPropertiesSet();
        assertTrue(true);
        assertEquals(fidp, interceptor.getObjectDefinitionSource());
    }

    /**
     * We just test invocation works in a success event. There is no need to
     * test  access denied events as the abstract parent enforces that logic,
     * which is extensively tested separately.
     *
     * @throws Throwable DOCUMENT ME!
     */
    public void testSuccessfulInvocation() throws Throwable {
        // Setup the FilterSecurityInterceptor
        FilterSecurityInterceptor interceptor = new FilterSecurityInterceptor();
        interceptor.setAccessDecisionManager(new MockAccessDecisionManager());
        interceptor.setAuthenticationManager(new MockAuthenticationManager());
        interceptor.setRunAsManager(new MockRunAsManager());
        interceptor.setApplicationContext(MockApplicationContext.getContext());

        // Setup a mock config attribute definition
        ConfigAttributeDefinition def = new ConfigAttributeDefinition();
        def.addConfigAttribute(new SecurityConfig("MOCK_OK"));

        MockFilterInvocationDefinitionMap mockSource = new MockFilterInvocationDefinitionMap("/secure/page.html",
                def);
        interceptor.setObjectDefinitionSource(mockSource);

        // Setup our expectation that the filter chain will be invoked, as access is granted
        MockFilterChain chain = new MockFilterChain(true);

        // Setup our HTTP request and response
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/secure/page.html");

        // Setup a Context
        SecureContext context = new SecureContextImpl();
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test",
                "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("MOCK_OK")});
        context.setAuthentication(token);
        ContextHolder.setContext(context);

        // Create and test our secure object
        FilterInvocation fi = new FilterInvocation(request, response, chain);
        interceptor.invoke(fi);

        // Destroy the Context
        ContextHolder.setContext(null);
    }

    //~ Inner Classes ==========================================================

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
