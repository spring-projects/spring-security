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

package org.springframework.security.ui.x509;

import junit.framework.TestCase;

import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationManager;
import org.springframework.security.BadCredentialsException;
import org.springframework.security.MockAuthenticationManager;

import org.springframework.security.context.SecurityContextHolder;

import org.springframework.security.providers.x509.X509AuthenticationToken;
import org.springframework.security.providers.x509.X509TestUtils;

import org.springframework.security.ui.AbstractProcessingFilter;

import org.springframework.security.util.MockFilterChain;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.security.cert.X509Certificate;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;


/**
 * Tests {@link org.springframework.security.ui.x509.X509ProcessingFilter}.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class X509ProcessingFilterTests extends TestCase {
    //~ Constructors ===================================================================================================

    public X509ProcessingFilterTests() {
        super();
    }

    public X509ProcessingFilterTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

    public void testAuthenticationIsNullWithNoCertificate()
        throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = new MockFilterChain(true);

        AuthenticationManager authMgr = new MockX509AuthenticationManager();
        X509ProcessingFilter filter = new X509ProcessingFilter();

        filter.setAuthenticationManager(authMgr);

        SecurityContextHolder.getContext().setAuthentication(null);
        filter.doFilter(request, response, chain);

        Object lastException = request.getSession()
                                      .getAttribute(AbstractProcessingFilter.SPRING_SECURITY_LAST_EXCEPTION_KEY);

        assertNull("Authentication should be null", SecurityContextHolder.getContext().getAuthentication());
        assertTrue("BadCredentialsException should have been thrown", lastException instanceof BadCredentialsException);
    }

    public void testDoFilterWithNonHttpServletRequestDetected()
        throws Exception {
        X509ProcessingFilter filter = new X509ProcessingFilter();

        try {
            filter.doFilter(null, new MockHttpServletResponse(), new MockFilterChain(false));
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertEquals("Can only process HttpServletRequest", expected.getMessage());
        }
    }

    public void testDoFilterWithNonHttpServletResponseDetected()
        throws Exception {
        X509ProcessingFilter filter = new X509ProcessingFilter();

        try {
            filter.doFilter(new MockHttpServletRequest(null, null), null, new MockFilterChain(false));
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertEquals("Can only process HttpServletResponse", expected.getMessage());
        }
    }

    public void testFailedAuthentication() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = new MockFilterChain(true);

        request.setAttribute("javax.servlet.request.X509Certificate",
            new X509Certificate[] {X509TestUtils.buildTestCertificate()});

        AuthenticationManager authMgr = new MockAuthenticationManager(false);

        SecurityContextHolder.getContext().setAuthentication(null);

        X509ProcessingFilter filter = new X509ProcessingFilter();

        filter.setAuthenticationManager(authMgr);
        filter.afterPropertiesSet();
        filter.init(null);
        filter.doFilter(request, response, chain);
        filter.destroy();

        Authentication result = SecurityContextHolder.getContext().getAuthentication();

        assertNull(result);
    }

    public void testNeedsAuthenticationManager() throws Exception {
        X509ProcessingFilter filter = new X509ProcessingFilter();

        try {
            filter.afterPropertiesSet();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException failed) {
            // ignored
        }
    }

    public void testNormalOperation() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = new MockFilterChain(true);

        request.setAttribute("javax.servlet.request.X509Certificate",
            new X509Certificate[] {X509TestUtils.buildTestCertificate()});

        AuthenticationManager authMgr = new MockX509AuthenticationManager();

        SecurityContextHolder.getContext().setAuthentication(null);

        X509ProcessingFilter filter = new X509ProcessingFilter();

        filter.setAuthenticationManager(authMgr);
        filter.afterPropertiesSet();
        filter.init(null);
        filter.doFilter(request, response, chain);
        filter.destroy();

        Authentication result = SecurityContextHolder.getContext().getAuthentication();

        assertNotNull(result);
    }

    //~ Inner Classes ==================================================================================================

    private static class MockX509AuthenticationManager implements AuthenticationManager {
        public Authentication authenticate(Authentication a) {
            if (!(a instanceof X509AuthenticationToken)) {
                TestCase.fail("Needed an X509Authentication token but found " + a);
            }

            if (a.getCredentials() == null) {
                throw new BadCredentialsException("Mock authentication manager rejecting null certificate");
            }

            return a;
        }
    }
}
