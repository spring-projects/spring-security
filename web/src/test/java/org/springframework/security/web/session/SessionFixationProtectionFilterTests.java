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
public class SessionFixationProtectionFilterTests {

    @After
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void newSessionShouldNotBeCreatedIfSessionExistsAndUserIsNotAuthenticated() throws Exception {
        SecurityContextRepository repo = mock(SecurityContextRepository.class);
        SessionFixationProtectionFilter filter = new SessionFixationProtectionFilter(repo);
        HttpServletRequest request = new MockHttpServletRequest();
        String sessionId = request.getSession().getId();

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertEquals(sessionId, request.getSession().getId());
    }

    @Test
    public void strategyIsNotInvokedIfSecurityContextAlreadyExistsForRequest() throws Exception {
        SecurityContextRepository repo = mock(SecurityContextRepository.class);
        AuthenticatedSessionStrategy strategy = mock(AuthenticatedSessionStrategy.class);
        // mock that repo contains a security context
        when(repo.containsContext(any(HttpServletRequest.class))).thenReturn(true);
        SessionFixationProtectionFilter filter = new SessionFixationProtectionFilter(repo);
        filter.setAuthenticatedSessionStrategy(strategy);
        HttpServletRequest request = new MockHttpServletRequest();
        authenticateUser();

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        verifyZeroInteractions(strategy);
    }

    @Test
    public void strategyIsNotInvokedIfAuthenticationIsNull() throws Exception {
        SecurityContextRepository repo = mock(SecurityContextRepository.class);
        AuthenticatedSessionStrategy strategy = mock(AuthenticatedSessionStrategy.class);
        SessionFixationProtectionFilter filter = new SessionFixationProtectionFilter(repo);
        filter.setAuthenticatedSessionStrategy(strategy);
        HttpServletRequest request = new MockHttpServletRequest();

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        verifyZeroInteractions(strategy);
    }

    @Test
    public void strategyIsInvokedIfUserIsNewlyAuthenticated() throws Exception {
        SecurityContextRepository repo = mock(SecurityContextRepository.class);
        // repo will return false to containsContext()
        AuthenticatedSessionStrategy strategy = mock(AuthenticatedSessionStrategy.class);
        SessionFixationProtectionFilter filter = new SessionFixationProtectionFilter(repo);
        filter.setAuthenticatedSessionStrategy(strategy);
        HttpServletRequest request = new MockHttpServletRequest();
        authenticateUser();

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        verify(strategy).onAuthenticationSuccess(any(Authentication.class), any(HttpServletRequest.class), any(HttpServletResponse.class));
    }

    private void authenticateUser() {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("user", "pass"));
    }
}
