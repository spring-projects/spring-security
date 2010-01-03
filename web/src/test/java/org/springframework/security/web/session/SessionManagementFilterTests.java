package org.springframework.security.web.session;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

import javax.servlet.FilterChain;
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
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * @author Luke Taylor
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
        filter.setSessionAuthenticationStrategy(strategy);
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
        filter.setSessionAuthenticationStrategy(strategy);
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
        filter.setSessionAuthenticationStrategy(strategy);
        HttpServletRequest request = new MockHttpServletRequest();
        authenticateUser();

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        verify(strategy).onAuthentication(any(Authentication.class), any(HttpServletRequest.class), any(HttpServletResponse.class));
        // Check that it is only applied once to the request
        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
        verifyNoMoreInteractions(strategy);
    }

    @Test
    public void strategyFailureInvokesFailureHandler() throws Exception {
        SecurityContextRepository repo = mock(SecurityContextRepository.class);
        // repo will return false to containsContext()
        SessionAuthenticationStrategy strategy = mock(SessionAuthenticationStrategy.class);

        AuthenticationFailureHandler failureHandler = mock(AuthenticationFailureHandler.class);
        SessionManagementFilter filter = new SessionManagementFilter(repo);
        filter.setAuthenticationFailureHandler(failureHandler);
        filter.setSessionAuthenticationStrategy(strategy);
        HttpServletRequest request = new MockHttpServletRequest();
        HttpServletResponse response = new MockHttpServletResponse();
        FilterChain fc = mock(FilterChain.class);
        authenticateUser();
        SessionAuthenticationException exception = new SessionAuthenticationException("Failure");
        doThrow(exception).when(strategy).onAuthentication(
                SecurityContextHolder.getContext().getAuthentication(), request, response);

        filter.doFilter(request,response, fc);
        verifyZeroInteractions(fc);
        verify(failureHandler).onAuthenticationFailure(request, response, exception);
    }

    @Test
    public void responseIsRedirectedToTimeoutUrlIfSetAndSessionIsInvalid() throws Exception {
        SecurityContextRepository repo = mock(SecurityContextRepository.class);
        // repo will return false to containsContext()
        SessionAuthenticationStrategy strategy = mock(SessionAuthenticationStrategy.class);
        SessionManagementFilter filter = new SessionManagementFilter(repo);
        filter.setSessionAuthenticationStrategy(strategy);
        filter.setRedirectStrategy(new DefaultRedirectStrategy());
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
        FilterChain fc = mock(FilterChain.class);
        filter.doFilter(request, response, fc);
        verifyZeroInteractions(fc);

        assertEquals("/timedOut", response.getRedirectedUrl());
    }

    private void authenticateUser() {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("user", "pass"));
    }
}
