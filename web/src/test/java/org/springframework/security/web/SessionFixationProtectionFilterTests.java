package org.springframework.security.web;

import static org.junit.Assert.*;

import javax.servlet.http.HttpServletRequest;

import org.junit.After;
import org.junit.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.TestingAuthenticationToken;
import org.springframework.security.web.SessionFixationProtectionFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

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
    public void newSessionShouldNotBeCreatedIfNoSessionExists() throws Exception {
        SessionFixationProtectionFilter filter = new SessionFixationProtectionFilter();
        HttpServletRequest request = new MockHttpServletRequest();
        authenticateUser();

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertNull(request.getSession(false));
    }

    @Test
    public void newSessionBeCreatedIfAuthenticatedOccurredDuringRequest() throws Exception {
        SessionFixationProtectionFilter filter = new SessionFixationProtectionFilter();
        HttpServletRequest request = new MockHttpServletRequest();
        String sessionId = request.getSession().getId();
        authenticateUser();

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertFalse(sessionId.equals(request.getSession().getId()));
    }

    @Test
    public void newSessionShouldNotBeCreatedIfSessionExistsAndUserIsNotAuthenticated() throws Exception {
        SessionFixationProtectionFilter filter = new SessionFixationProtectionFilter();
        HttpServletRequest request = new MockHttpServletRequest();
        String sessionId = request.getSession().getId();

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertEquals(sessionId, request.getSession().getId());
    }

    @Test
    public void newSessionShouldNotBeCreatedIfUserIsAlreadyAuthenticated() throws Exception {
        SessionFixationProtectionFilter filter = new SessionFixationProtectionFilter();
        HttpServletRequest request = new MockHttpServletRequest();
        String sessionId = request.getSession().getId();
        authenticateUser();
        request.getSession().setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                SecurityContextHolder.getContext());

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertEquals(sessionId, request.getSession().getId());
    }

    private void authenticateUser() {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("user", "pass"));
    }
}
