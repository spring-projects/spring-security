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

package org.springframework.security.web;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import junit.framework.TestCase;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.AccessDeniedException;
import org.springframework.security.BadCredentialsException;
import org.springframework.security.MockAuthenticationEntryPoint;
import org.springframework.security.MockPortResolver;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.AnonymousAuthenticationToken;
import org.springframework.security.util.AuthorityUtils;
import org.springframework.security.web.AccessDeniedHandlerImpl;
import org.springframework.security.web.ExceptionTranslationFilter;
import org.springframework.security.web.savedrequest.SavedRequest;

/**
 * Tests {@link ExceptionTranslationFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ExceptionTranslationFilterTests extends TestCase {
    //~ Methods ========================================================================================================

    protected void tearDown() throws Exception {
        super.tearDown();
        SecurityContextHolder.clearContext();
    }

    private static String getSavedRequestUrl(HttpServletRequest request) {
        HttpSession session = request.getSession(false);

        if (session == null) {
            return null;
        }

        SavedRequest savedRequest = (SavedRequest) session.getAttribute(SavedRequest.SPRING_SECURITY_SAVED_REQUEST_KEY);

        return savedRequest.getFullRequestUrl();
    }

    public void testAccessDeniedWhenAnonymous() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/secure/page.html");
        request.setServerPort(80);
        request.setScheme("http");
        request.setServerName("www.example.com");
        request.setContextPath("/mycontext");
        request.setRequestURI("/mycontext/secure/page.html");

        // Setup the FilterChain to thrown an access denied exception
        MockFilterChain chain = new MockFilterChain(true, false, false, false);

        // Setup SecurityContextHolder, as filter needs to check if user is
        // anonymous
        SecurityContextHolder.getContext().setAuthentication(
                new AnonymousAuthenticationToken("ignored", "ignored", AuthorityUtils.createAuthorityList("IGNORED")));

        // Test
        ExceptionTranslationFilter filter = new ExceptionTranslationFilter();
        filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint("/login.jsp"));

        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);
        assertEquals("/mycontext/login.jsp", response.getRedirectedUrl());
        assertEquals("http://www.example.com/mycontext/secure/page.html", getSavedRequestUrl(request));
    }

    public void testAccessDeniedWhenNonAnonymous() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/secure/page.html");

        // Setup the FilterChain to thrown an access denied exception
        MockFilterChain chain = new MockFilterChain(true, false, false, false);

        // Setup SecurityContextHolder, as filter needs to check if user is
        // anonymous
        SecurityContextHolder.getContext().setAuthentication(null);

        // Setup a new AccessDeniedHandlerImpl that will do a "forward"
        AccessDeniedHandlerImpl adh = new AccessDeniedHandlerImpl();
        adh.setErrorPage("/error.jsp");

        // Test
        ExceptionTranslationFilter filter = new ExceptionTranslationFilter();
        filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint("/login.jsp"));
        filter.setAccessDeniedHandler(adh);

        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);
        assertEquals(403, response.getStatus());
        assertEquals(AccessDeniedException.class, request.getAttribute(
                AccessDeniedHandlerImpl.SPRING_SECURITY_ACCESS_DENIED_EXCEPTION_KEY).getClass());
    }

    public void testGettersSetters() {
        ExceptionTranslationFilter filter = new ExceptionTranslationFilter();

        filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint("/login.jsp"));
        assertTrue(filter.getAuthenticationEntryPoint() != null);

        filter.setPortResolver(new MockPortResolver(80, 443));
        assertTrue(filter.getPortResolver() != null);
    }

    public void testRedirectedToLoginFormAndSessionShowsOriginalTargetWhenAuthenticationException() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/secure/page.html");
        request.setServerPort(80);
        request.setScheme("http");
        request.setServerName("www.example.com");
        request.setContextPath("/mycontext");
        request.setRequestURI("/mycontext/secure/page.html");

        // Setup the FilterChain to thrown an authentication failure exception
        MockFilterChain chain = new MockFilterChain(false, true, false, false);

        // Test
        ExceptionTranslationFilter filter = new ExceptionTranslationFilter();
        filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint("/login.jsp"));
        filter.setPortResolver(new MockPortResolver(80, 443));
        /*
         * Disabled the call to afterPropertiesSet as it requires
         * applicationContext to be injected before it is invoked. We do not
         * have this filter configured in IOC for this test hence no
         * ApplicationContext
         */
        // filter.afterPropertiesSet();
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);
        assertEquals("/mycontext/login.jsp", response.getRedirectedUrl());
        assertEquals("http://www.example.com/mycontext/secure/page.html", getSavedRequestUrl(request));
    }

    public void testRedirectedToLoginFormAndSessionShowsOriginalTargetWithExoticPortWhenAuthenticationException()
            throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/secure/page.html");
        request.setServerPort(8080);
        request.setScheme("http");
        request.setServerName("www.example.com");
        request.setContextPath("/mycontext");
        request.setRequestURI("/mycontext/secure/page.html");

        // Setup the FilterChain to thrown an authentication failure exception
        MockFilterChain chain = new MockFilterChain(false, true, false, false);

        // Test
        ExceptionTranslationFilter filter = new ExceptionTranslationFilter();
        filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint("/login.jsp"));
        filter.setPortResolver(new MockPortResolver(8080, 8443));
        /*
         * Disabled the call to afterPropertiesSet as it requires
         * applicationContext to be injected before it is invoked. We do not
         * have this filter configured in IOC for this test hence no
         * ApplicationContext
         */
        // filter.afterPropertiesSet();
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);
        assertEquals("/mycontext/login.jsp", response.getRedirectedUrl());
        assertEquals("http://www.example.com:8080/mycontext/secure/page.html", getSavedRequestUrl(request));
    }

    public void testSavedRequestIsNotStoredForPostIfJustUseSaveRequestOnGetIsSet() throws Exception {
        ExceptionTranslationFilter filter = new ExceptionTranslationFilter();
        filter.setJustUseSavedRequestOnGet(true);
        filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint("/login.jsp"));
        filter.setPortResolver(new MockPortResolver(8080, 8443));
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockFilterChain chain = new MockFilterChain(false, true, false, false);
        request.setMethod("POST");
        filter.doFilter(request, new MockHttpServletResponse(), chain);
        assertTrue(request.getSession().getAttribute(SavedRequest.SPRING_SECURITY_SAVED_REQUEST_KEY) == null);
    }

    public void testStartupDetectsMissingAuthenticationEntryPoint() throws Exception {
        ExceptionTranslationFilter filter = new ExceptionTranslationFilter();

        try {
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
            assertEquals("authenticationEntryPoint must be specified", expected.getMessage());
        }
    }

    public void testStartupDetectsMissingPortResolver() throws Exception {
        ExceptionTranslationFilter filter = new ExceptionTranslationFilter();
        filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint("/login.jsp"));
        filter.setPortResolver(null);

        try {
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
            assertEquals("portResolver must be specified", expected.getMessage());
        }
    }

    public void testSuccessfulAccessGrant() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/secure/page.html");

        // Setup the FilterChain to thrown no exceptions
        MockFilterChain chain = new MockFilterChain(false, false, false, false);

        // Test
        ExceptionTranslationFilter filter = new ExceptionTranslationFilter();
        filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint("/login.jsp"));

        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);
    }

    public void testSuccessfulStartupAndShutdownDown() throws Exception {
        ExceptionTranslationFilter filter = new ExceptionTranslationFilter();

        filter.init(null);
        filter.destroy();
        assertTrue(true);
    }

    public void testThrowIOException() throws Exception {
        ExceptionTranslationFilter filter = new ExceptionTranslationFilter();

        filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint(""));
        /*
         * Disabled the call to afterPropertiesSet as it requires
         * applicationContext to be injected before it is invoked. We do not
         * have this filter configured in IOC for this test hence no
         * ApplicationContext
         */
        // filter.afterPropertiesSet();
        try {
            filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), new MockFilterChain(false,
                    false, false, true));
            fail("Should have thrown IOException");
        }
        catch (IOException e) {
            assertNull("The IOException thrown should not have been wrapped", e.getCause());
        }
    }

    public void testThrowServletException() throws Exception {
        ExceptionTranslationFilter filter = new ExceptionTranslationFilter();

        filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint(""));
        /*
         * Disabled the call to afterPropertiesSet as it requires
         * applicationContext to be injected before it is invoked. We do not
         * have this filter configured in IOC for this test hence no
         * ApplicationContext
         */
        // filter.afterPropertiesSet();
        try {
            filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), new MockFilterChain(false,
                    false, true, false));
            fail("Should have thrown ServletException");
        }
        catch (ServletException e) {
            assertNull("The ServletException thrown should not have been wrapped", e.getCause());
        }
    }

    // ~ Inner Classes =================================================================================================

    private class MockFilterChain implements FilterChain {
        private boolean throwAccessDenied;

        private boolean throwAuthenticationFailure;

        private boolean throwIOException;

        private boolean throwServletException;

        public MockFilterChain(boolean throwAccessDenied, boolean throwAuthenticationFailure,
                boolean throwServletException, boolean throwIOException) {
            this.throwAccessDenied = throwAccessDenied;
            this.throwAuthenticationFailure = throwAuthenticationFailure;
            this.throwServletException = throwServletException;
            this.throwIOException = throwIOException;
        }

        public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
            if (throwAccessDenied) {
                throw new AccessDeniedException("As requested");
            }

            if (throwAuthenticationFailure) {
                throw new BadCredentialsException("As requested");
            }

            if (throwServletException) {
                throw new ServletException("As requested");
            }

            if (throwIOException) {
                throw new IOException("As requested");
            }
        }
    }
}
