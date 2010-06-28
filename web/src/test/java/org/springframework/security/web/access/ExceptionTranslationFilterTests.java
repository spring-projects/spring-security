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

package org.springframework.security.web.access;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.MockPortResolver;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.util.ThrowableAnalyzer;

/**
 * Tests {@link ExceptionTranslationFilter}.
 *
 * @author Ben Alex
 */
public class ExceptionTranslationFilterTests {

    @After
    @Before
    public void clearContext() throws Exception {
        SecurityContextHolder.clearContext();
    }

    private static String getSavedRequestUrl(HttpServletRequest request) {
        HttpSession session = request.getSession(false);

        if (session == null) {
            return null;
        }

        DefaultSavedRequest savedRequest = (DefaultSavedRequest) session.getAttribute(WebAttributes.SAVED_REQUEST);

        return savedRequest.getRedirectUrl();
    }

    @Test
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
        FilterChain fc = mock(FilterChain.class);
        doThrow(new AccessDeniedException("")).when(fc).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

        // Setup SecurityContextHolder, as filter needs to check if user is
        // anonymous
        SecurityContextHolder.getContext().setAuthentication(
                new AnonymousAuthenticationToken("ignored", "ignored", AuthorityUtils.createAuthorityList("IGNORED")));

        // Test
        ExceptionTranslationFilter filter = new ExceptionTranslationFilter();
        filter.setAuthenticationEntryPoint(mockEntryPoint());
        filter.setAuthenticationTrustResolver(new AuthenticationTrustResolverImpl());

        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, fc);
        assertEquals("/mycontext/login.jsp", response.getRedirectedUrl());
        assertEquals("http://www.example.com/mycontext/secure/page.html", getSavedRequestUrl(request));
    }

    @Test
    public void testAccessDeniedWhenNonAnonymous() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/secure/page.html");

        // Setup the FilterChain to thrown an access denied exception
        FilterChain fc = mock(FilterChain.class);
        doThrow(new AccessDeniedException("")).when(fc).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

        // Setup SecurityContextHolder, as filter needs to check if user is
        // anonymous
        SecurityContextHolder.clearContext();

        // Setup a new AccessDeniedHandlerImpl that will do a "forward"
        AccessDeniedHandlerImpl adh = new AccessDeniedHandlerImpl();
        adh.setErrorPage("/error.jsp");

        // Test
        ExceptionTranslationFilter filter = new ExceptionTranslationFilter();
        filter.setAuthenticationEntryPoint(mockEntryPoint());
        filter.setAccessDeniedHandler(adh);

        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, fc);
        assertEquals(403, response.getStatus());
        assertEquals(AccessDeniedException.class, request.getAttribute(WebAttributes.ACCESS_DENIED_403).getClass());
    }

    @Test
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
        FilterChain fc = mock(FilterChain.class);
        doThrow(new BadCredentialsException("")).when(fc).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

        // Test
        ExceptionTranslationFilter filter = new ExceptionTranslationFilter();
        filter.setAuthenticationEntryPoint(mockEntryPoint());
        filter.afterPropertiesSet();
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, fc);
        assertEquals("/mycontext/login.jsp", response.getRedirectedUrl());
        assertEquals("http://www.example.com/mycontext/secure/page.html", getSavedRequestUrl(request));
    }

    @Test
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
        FilterChain fc = mock(FilterChain.class);
        doThrow(new BadCredentialsException("")).when(fc).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

        // Test
        ExceptionTranslationFilter filter = new ExceptionTranslationFilter();
        filter.setAuthenticationEntryPoint(mockEntryPoint());
        HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
        requestCache.setPortResolver(new MockPortResolver(8080, 8443));
        filter.setRequestCache(requestCache);
        filter.afterPropertiesSet();
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, fc);
        assertEquals("/mycontext/login.jsp", response.getRedirectedUrl());
        assertEquals("http://www.example.com:8080/mycontext/secure/page.html", getSavedRequestUrl(request));
    }

    @Test(expected=IllegalArgumentException.class)
    public void testStartupDetectsMissingAuthenticationEntryPoint() throws Exception {
        ExceptionTranslationFilter filter = new ExceptionTranslationFilter();
        filter.setThrowableAnalyzer(mock(ThrowableAnalyzer.class));

        filter.afterPropertiesSet();
    }

    @Test(expected=IllegalArgumentException.class)
    public void testStartupDetectsMissingRequestCache() throws Exception {
        ExceptionTranslationFilter filter = new ExceptionTranslationFilter();
        filter.setAuthenticationEntryPoint(mockEntryPoint());

        filter.setRequestCache(null);
    }

    public void testSuccessfulAccessGrant() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/secure/page.html");

        // Test
        ExceptionTranslationFilter filter = new ExceptionTranslationFilter();
        filter.setAuthenticationEntryPoint(mockEntryPoint());

        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, mock(FilterChain.class));
    }

    @Test
    public void testThrowIOException() throws Exception {
        ExceptionTranslationFilter filter = new ExceptionTranslationFilter();

        filter.setAuthenticationEntryPoint(mockEntryPoint());
        filter.afterPropertiesSet();
        FilterChain fc = mock(FilterChain.class);
        doThrow(new IOException()).when(fc).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
        try {
            filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), fc);
            fail("Should have thrown IOException");
        }
        catch (IOException e) {
            assertNull("The IOException thrown should not have been wrapped", e.getCause());
        }
    }

    @Test
    public void testThrowServletException() throws Exception {
        ExceptionTranslationFilter filter = new ExceptionTranslationFilter();

        filter.setAuthenticationEntryPoint(mockEntryPoint());
        filter.afterPropertiesSet();
        FilterChain fc = mock(FilterChain.class);
        doThrow(new ServletException()).when(fc).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
        try {
            filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), fc);
            fail("Should have thrown ServletException");
        }
        catch (ServletException e) {
            assertNull("The ServletException thrown should not have been wrapped", e.getCause());
        }
    }

    private AuthenticationEntryPoint mockEntryPoint() {
        return new AuthenticationEntryPoint() {
            public void commence(HttpServletRequest request, HttpServletResponse response,
                    AuthenticationException authException) throws IOException, ServletException {
                response.sendRedirect(request.getContextPath() + "/login.jsp");
            }
        };
    }
}
