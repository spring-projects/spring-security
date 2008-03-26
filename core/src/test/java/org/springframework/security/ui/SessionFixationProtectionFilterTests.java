package org.springframework.security.ui;

import static org.junit.Assert.*;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.TestingAuthenticationToken;

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
        
        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
        
        assertNull(request.getSession(false));
    }

    @Test
    public void newSessionShouldNotBeCreatedIfUserIsAuthenticated() throws Exception {
        SessionFixationProtectionFilter filter = new SessionFixationProtectionFilter();
        HttpServletRequest request = new MockHttpServletRequest();
        String sessionId = request.getSession().getId();
        
        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
        
        assertEquals(sessionId, request.getSession().getId());
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
        
        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
        
        assertEquals(sessionId, request.getSession().getId());
    }    
    
    @Test
    public void newSessionShouldBeCreatedIfAuthenticationOccursDuringRequest() throws Exception {
        SessionFixationProtectionFilter filter = new SessionFixationProtectionFilter();
        HttpServletRequest request = new MockHttpServletRequest();
        String sessionId = request.getSession().getId();
        
        filter.doFilter(request, new MockHttpServletResponse(), new UserAuthenticatingFilterChain());
        
        assertFalse(sessionId.equals(request.getSession().getId()));         
    }
    
    @Test
    public void newSessionShouldBeCreatedIfAuthenticationAndRedirectOccursDuringRequest() throws Exception {
        SessionFixationProtectionFilter filter = new SessionFixationProtectionFilter();
        HttpServletRequest request = new MockHttpServletRequest();
        String sessionId = request.getSession().getId();
        
        AuthenticateAndRedirectFilterChain chain = new AuthenticateAndRedirectFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);
        
        assertTrue(chain.getResponse() instanceof 
                SessionFixationProtectionFilter.SessionFixationProtectionResponseWrapper);
        assertTrue("New session should have been created by session wrapper",
                ((SessionFixationProtectionFilter.SessionFixationProtectionResponseWrapper)chain.getResponse()).isNewSessionStarted());
        assertFalse(sessionId.equals(request.getSession().getId()));
    }
    
    @Test
    public void wrapperSendErrorCreatesNewSession() throws Exception {
        authenticateUser();
        SessionFixationProtectionFilter filter = new SessionFixationProtectionFilter();
        HttpServletRequest request = new MockHttpServletRequest();
        String sessionId = request.getSession().getId();
        SessionFixationProtectionFilter.SessionFixationProtectionResponseWrapper wrapper = 
            filter.new SessionFixationProtectionResponseWrapper(new MockHttpServletResponse(), request);
        wrapper.sendError(HttpServletResponse.SC_FORBIDDEN);
        assertFalse(sessionId.equals(request.getSession().getId()));
        
        // Message version
        request = new MockHttpServletRequest();
        sessionId = request.getSession().getId();
        wrapper = filter.new SessionFixationProtectionResponseWrapper(new MockHttpServletResponse(), request);
        wrapper.sendError(HttpServletResponse.SC_FORBIDDEN, "Hi. I'm your friendly forbidden message.");
        assertFalse(sessionId.equals(request.getSession().getId()));        
    }

    @Test
    public void wrapperRedirectCreatesNewSession() throws Exception {
        authenticateUser();
        SessionFixationProtectionFilter filter = new SessionFixationProtectionFilter();
        HttpServletRequest request = new MockHttpServletRequest();
        String sessionId = request.getSession().getId();
        SessionFixationProtectionFilter.SessionFixationProtectionResponseWrapper wrapper = 
            filter.new SessionFixationProtectionResponseWrapper(new MockHttpServletResponse(), request);
        wrapper.sendRedirect("/somelocation");
        assertFalse(sessionId.equals(request.getSession().getId()));
    }
    
    private void authenticateUser() {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("user", "pass", null));
    }
    
    private class UserAuthenticatingFilterChain implements FilterChain {
        public void doFilter(ServletRequest request, ServletResponse response) throws IOException { 
            authenticateUser();
        }
    }
    
    private class AuthenticateAndRedirectFilterChain extends UserAuthenticatingFilterChain{
        HttpServletResponse response;
        
        public void doFilter(ServletRequest request, ServletResponse response) throws IOException {
            super.doFilter(request, response);
            this.response = (HttpServletResponse)response;
            this.response.sendRedirect("/someUrl");
        }

        public HttpServletResponse getResponse() {
            return response;
        }
    }
}
