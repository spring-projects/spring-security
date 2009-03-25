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

package org.springframework.security.ui.webapp;

import javax.servlet.ServletException;

import junit.framework.TestCase;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.MockAuthenticationManager;
import org.springframework.security.ui.WebAuthenticationDetails;


/**
 * Tests {@link AuthenticationProcessingFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AuthenticationProcessingFilterTests extends TestCase {
    //~ Methods ========================================================================================================

    @Test
    public void testNormalOperation() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
        request.addParameter(AuthenticationProcessingFilter.SPRING_SECURITY_FORM_USERNAME_KEY, "rod");
        request.addParameter(AuthenticationProcessingFilter.SPRING_SECURITY_FORM_PASSWORD_KEY, "koala");

        AuthenticationProcessingFilter filter = new AuthenticationProcessingFilter();
        assertEquals("/j_spring_security_check", filter.getFilterProcessesUrl());
        filter.setAuthenticationManager(new MockAuthenticationManager(true));
        filter.init(null);

        Authentication result = filter.attemptAuthentication(request, new MockHttpServletResponse());
        assertTrue(result != null);
        assertEquals("rod", request.getSession().getAttribute(
                AuthenticationProcessingFilter.SPRING_SECURITY_LAST_USERNAME_KEY));
        assertEquals("127.0.0.1", ((WebAuthenticationDetails) result.getDetails()).getRemoteAddress());
    }

    @Test
    public void testNullPasswordHandledGracefully() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
        request.addParameter(AuthenticationProcessingFilter.SPRING_SECURITY_FORM_USERNAME_KEY, "rod");

        AuthenticationProcessingFilter filter = new AuthenticationProcessingFilter();
        filter.setAuthenticationManager(new MockAuthenticationManager(true));

        Authentication result = filter.attemptAuthentication(request, new MockHttpServletResponse());
        assertTrue(result != null);
    }

    @Test
    public void testNullUsernameHandledGracefully() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
        request.addParameter(AuthenticationProcessingFilter.SPRING_SECURITY_FORM_PASSWORD_KEY, "koala");

        AuthenticationProcessingFilter filter = new AuthenticationProcessingFilter();
        filter.setAuthenticationManager(new MockAuthenticationManager(true));

        Authentication result = filter.attemptAuthentication(request, new MockHttpServletResponse());
        assertTrue(result != null);
    }

    @Test
    public void testUsingDifferentParameterNamesWorksAsExpected() throws ServletException {
        AuthenticationProcessingFilter filter = new AuthenticationProcessingFilter();
        filter.setAuthenticationManager(new MockAuthenticationManager(true));
        filter.setUsernameParameter("x");
        filter.setPasswordParameter("y");

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
        request.addParameter("x", "rod");
        request.addParameter("y", "koala");

        Authentication result = filter.attemptAuthentication(request, new MockHttpServletResponse());
        assertTrue(result != null);
        assertEquals("127.0.0.1", ((WebAuthenticationDetails) result.getDetails()).getRemoteAddress());
    }

    @Test
    public void testSpacesAreTrimmedCorrectlyFromUsername() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
        request.addParameter(AuthenticationProcessingFilter.SPRING_SECURITY_FORM_USERNAME_KEY, " rod ");
        request.addParameter(AuthenticationProcessingFilter.SPRING_SECURITY_FORM_PASSWORD_KEY, "koala");

        AuthenticationProcessingFilter filter = new AuthenticationProcessingFilter();
        filter.setAuthenticationManager(new MockAuthenticationManager(true));

        Authentication result = filter.attemptAuthentication(request, new MockHttpServletResponse());
        assertEquals("rod", result.getName());
    }

    @Test
    public void testFailedAuthenticationThrowsException() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
        request.addParameter(AuthenticationProcessingFilter.SPRING_SECURITY_FORM_USERNAME_KEY, "rod");
        AuthenticationProcessingFilter filter = new AuthenticationProcessingFilter();
        filter.setAuthenticationManager(new MockAuthenticationManager(false));

        try {
            filter.attemptAuthentication(request, new MockHttpServletResponse());
            fail("Expected AuthenticationException");
        } catch (AuthenticationException e) {
        }

        // Check username has still been set
        assertEquals("rod", request.getSession().getAttribute(
                AuthenticationProcessingFilter.SPRING_SECURITY_LAST_USERNAME_KEY));
    }

    /**
     * SEC-571
     */
    @Test
    public void noSessionIsCreatedIfAllowSessionCreationIsFalse() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();

        AuthenticationProcessingFilter filter = new AuthenticationProcessingFilter();
        filter.setAllowSessionCreation(false);
        filter.setAuthenticationManager(new MockAuthenticationManager(true));

        filter.attemptAuthentication(request, new MockHttpServletResponse());

        assertNull(request.getSession(false));
    }
}
