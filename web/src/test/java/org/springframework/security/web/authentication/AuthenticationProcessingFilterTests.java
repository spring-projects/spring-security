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

package org.springframework.security.web.authentication;


import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

import javax.servlet.ServletException;

import junit.framework.TestCase;

import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;


/**
 * Tests {@link UsernamePasswordAuthenticationProcessingFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AuthenticationProcessingFilterTests extends TestCase {
    //~ Methods ========================================================================================================

    @Test
    public void testNormalOperation() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
        request.addParameter(UsernamePasswordAuthenticationProcessingFilter.SPRING_SECURITY_FORM_USERNAME_KEY, "rod");
        request.addParameter(UsernamePasswordAuthenticationProcessingFilter.SPRING_SECURITY_FORM_PASSWORD_KEY, "koala");

        UsernamePasswordAuthenticationProcessingFilter filter = new UsernamePasswordAuthenticationProcessingFilter();
        assertEquals("/j_spring_security_check", filter.getFilterProcessesUrl());
        filter.setAuthenticationManager(createAuthenticationManager());
        filter.init(null);

        Authentication result = filter.attemptAuthentication(request, new MockHttpServletResponse());
        assertTrue(result != null);
        assertEquals("rod", request.getSession().getAttribute(
                UsernamePasswordAuthenticationProcessingFilter.SPRING_SECURITY_LAST_USERNAME_KEY));
        assertEquals("127.0.0.1", ((WebAuthenticationDetails) result.getDetails()).getRemoteAddress());
    }

    @Test
    public void testNullPasswordHandledGracefully() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
        request.addParameter(UsernamePasswordAuthenticationProcessingFilter.SPRING_SECURITY_FORM_USERNAME_KEY, "rod");

        UsernamePasswordAuthenticationProcessingFilter filter = new UsernamePasswordAuthenticationProcessingFilter();
        filter.setAuthenticationManager(createAuthenticationManager());
        assertNotNull(filter.attemptAuthentication(request, new MockHttpServletResponse()));
    }

    @Test
    public void testNullUsernameHandledGracefully() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
        request.addParameter(UsernamePasswordAuthenticationProcessingFilter.SPRING_SECURITY_FORM_PASSWORD_KEY, "koala");

        UsernamePasswordAuthenticationProcessingFilter filter = new UsernamePasswordAuthenticationProcessingFilter();
        filter.setAuthenticationManager(createAuthenticationManager());
        assertNotNull(filter.attemptAuthentication(request, new MockHttpServletResponse()));
    }

    @Test
    public void testUsingDifferentParameterNamesWorksAsExpected() throws ServletException {
        UsernamePasswordAuthenticationProcessingFilter filter = new UsernamePasswordAuthenticationProcessingFilter();
        filter.setAuthenticationManager(createAuthenticationManager());
        filter.setUsernameParameter("x");
        filter.setPasswordParameter("y");

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
        request.addParameter("x", "rod");
        request.addParameter("y", "koala");

        Authentication result = filter.attemptAuthentication(request, new MockHttpServletResponse());
        assertNotNull(result);
        assertEquals("127.0.0.1", ((WebAuthenticationDetails) result.getDetails()).getRemoteAddress());
    }

    @Test
    public void testSpacesAreTrimmedCorrectlyFromUsername() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
        request.addParameter(UsernamePasswordAuthenticationProcessingFilter.SPRING_SECURITY_FORM_USERNAME_KEY, " rod ");
        request.addParameter(UsernamePasswordAuthenticationProcessingFilter.SPRING_SECURITY_FORM_PASSWORD_KEY, "koala");

        UsernamePasswordAuthenticationProcessingFilter filter = new UsernamePasswordAuthenticationProcessingFilter();
        filter.setAuthenticationManager(createAuthenticationManager());

        Authentication result = filter.attemptAuthentication(request, new MockHttpServletResponse());
        assertEquals("rod", result.getName());
    }

    @Test
    public void testFailedAuthenticationThrowsException() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
        request.addParameter(UsernamePasswordAuthenticationProcessingFilter.SPRING_SECURITY_FORM_USERNAME_KEY, "rod");
        UsernamePasswordAuthenticationProcessingFilter filter = new UsernamePasswordAuthenticationProcessingFilter();
        AuthenticationManager am = mock(AuthenticationManager.class);
        when(am.authenticate(any(Authentication.class))).thenThrow(new BadCredentialsException(""));
        filter.setAuthenticationManager(am);

        try {
            filter.attemptAuthentication(request, new MockHttpServletResponse());
            fail("Expected AuthenticationException");
        } catch (AuthenticationException e) {
        }

        // Check username has still been set
        assertEquals("rod", request.getSession().getAttribute(
                UsernamePasswordAuthenticationProcessingFilter.SPRING_SECURITY_LAST_USERNAME_KEY));
    }

    /**
     * SEC-571
     */
    @Test
    public void noSessionIsCreatedIfAllowSessionCreationIsFalse() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();

        UsernamePasswordAuthenticationProcessingFilter filter = new UsernamePasswordAuthenticationProcessingFilter();
        filter.setAllowSessionCreation(false);
        filter.setAuthenticationManager(createAuthenticationManager());

        filter.attemptAuthentication(request, new MockHttpServletResponse());

        assertNull(request.getSession(false));
    }

    private AuthenticationManager createAuthenticationManager() {
        AuthenticationManager am = mock(AuthenticationManager.class);
        when(am.authenticate(any(Authentication.class))).thenAnswer(new Answer<Authentication>() {
            public Authentication answer(InvocationOnMock invocation) throws Throwable {
                return (Authentication) invocation.getArguments()[0];
            }
        });

        return am;
    }

}
