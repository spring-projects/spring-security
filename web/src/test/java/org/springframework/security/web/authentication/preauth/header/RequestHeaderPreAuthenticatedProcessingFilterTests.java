package org.springframework.security.web.authentication.preauth.header;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.MockAuthenticationManager;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedCredentialsNotFoundException;
import org.springframework.security.web.authentication.preauth.RequestHeaderPreAuthenticatedProcessingFilter;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class RequestHeaderPreAuthenticatedProcessingFilterTests {

    @After
    @Before
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test(expected = PreAuthenticatedCredentialsNotFoundException.class)
    public void rejectsMissingHeader() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        RequestHeaderPreAuthenticatedProcessingFilter filter = new RequestHeaderPreAuthenticatedProcessingFilter();
        filter.getOrder();

        filter.doFilter(request, response, chain);
    }

    @Test
    public void defaultsToUsingSiteminderHeader() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("SM_USER", "cat");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        RequestHeaderPreAuthenticatedProcessingFilter filter = new RequestHeaderPreAuthenticatedProcessingFilter();
        filter.setAuthenticationManager(new MockAuthenticationManager());

        filter.doFilter(request, response, chain);
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals("cat", SecurityContextHolder.getContext().getAuthentication().getName());
        assertEquals("N/A", SecurityContextHolder.getContext().getAuthentication().getCredentials());
    }

    @Test
    public void alternativeHeaderNameIsSupported() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("myUsernameHeader", "wolfman");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        RequestHeaderPreAuthenticatedProcessingFilter filter = new RequestHeaderPreAuthenticatedProcessingFilter();
        filter.setAuthenticationManager(new MockAuthenticationManager());
        filter.setPrincipalRequestHeader("myUsernameHeader");

        filter.doFilter(request, response, chain);
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals("wolfman", SecurityContextHolder.getContext().getAuthentication().getName());
    }

    @Test
    public void credentialsAreRetrievedIfHeaderNameIsSet() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        RequestHeaderPreAuthenticatedProcessingFilter filter = new RequestHeaderPreAuthenticatedProcessingFilter();
        filter.setAuthenticationManager(new MockAuthenticationManager());
        filter.setCredentialsRequestHeader("myCredentialsHeader");
        request.addHeader("SM_USER", "cat");
        request.addHeader("myCredentialsHeader", "catspassword");

        filter.doFilter(request, response, chain);
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals("catspassword", SecurityContextHolder.getContext().getAuthentication().getCredentials());
    }

}
