package org.springframework.security.web.session;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class SessionManagementFilterTests {

    @After
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void newSessionShouldNotBeCreatedIfSessionExistsAndUserIsNotAuthenticated() throws Exception {
        SecurityContextRepository repo = mock(SecurityContextRepository.class);
        SessionManagementFilter filter = new SessionManagementFilter(repo);
        HttpServletRequest request = new MockHttpServletRequest();
        String sessionId = request.getSession().getId();

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertEquals(sessionId, request.getSession().getId());
    }

    @Test
    public void strategyIsNotInvokedIfSecurityContextAlreadyExistsForRequest() throws Exception {
        SecurityContextRepository repo = mock(SecurityContextRepository.class);
        SessionAuthenticationStrategy strategy = mock(SessionAuthenticationStrategy.class);
        // mock that repo contains a security context
        when(repo.containsContext(any(HttpServletRequest.class))).thenReturn(true);
        SessionManagementFilter filter = new SessionManagementFilter(repo);
        filter.setAuthenticatedSessionStrategy(strategy);
        HttpServletRequest request = new MockHttpServletRequest();
        authenticateUser();

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        verifyZeroInteractions(strategy);
    }

    @Test
    public void strategyIsNotInvokedIfAuthenticationIsNull() throws Exception {
        SecurityContextRepository repo = mock(SecurityContextRepository.class);
        SessionAuthenticationStrategy strategy = mock(SessionAuthenticationStrategy.class);
        SessionManagementFilter filter = new SessionManagementFilter(repo);
        filter.setAuthenticatedSessionStrategy(strategy);
        HttpServletRequest request = new MockHttpServletRequest();

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        verifyZeroInteractions(strategy);
    }

    @Test
    public void strategyIsInvokedIfUserIsNewlyAuthenticated() throws Exception {
        SecurityContextRepository repo = mock(SecurityContextRepository.class);
        // repo will return false to containsContext()
        SessionAuthenticationStrategy strategy = mock(SessionAuthenticationStrategy.class);
        SessionManagementFilter filter = new SessionManagementFilter(repo);
        filter.setAuthenticatedSessionStrategy(strategy);
        HttpServletRequest request = new MockHttpServletRequest();
        authenticateUser();

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        verify(strategy).onAuthentication(any(Authentication.class), any(HttpServletRequest.class), any(HttpServletResponse.class));
        // Check that it is only applied once to the request
        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
        verifyNoMoreInteractions(strategy);
    }

    @Test
    public void responseIsRedirectedToTimeoutUrlIfSetAndSessionIsInvalid() throws Exception {
        SecurityContextRepository repo = mock(SecurityContextRepository.class);
        // repo will return false to containsContext()
        SessionAuthenticationStrategy strategy = mock(SessionAuthenticationStrategy.class);
        SessionManagementFilter filter = new SessionManagementFilter(repo);
        filter.setAuthenticatedSessionStrategy(strategy);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestedSessionId("xxx");
        request.setRequestedSessionIdValid(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());
        assertNull(response.getRedirectedUrl());

        // Now set a redirect URL
        request = new MockHttpServletRequest();
        request.setRequestedSessionId("xxx");
        request.setRequestedSessionIdValid(false);
        filter.setInvalidSessionUrl("/timedOut");
        filter.doFilter(request, response, new MockFilterChain());
        assertEquals("/timedOut", response.getRedirectedUrl());
    }

    private void authenticateUser() {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("user", "pass"));
    }
}
