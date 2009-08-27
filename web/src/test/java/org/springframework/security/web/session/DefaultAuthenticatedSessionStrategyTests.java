package org.springframework.security.web.session;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.concurrent.SessionRegistry;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.savedrequest.SavedRequest;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class DefaultAuthenticatedSessionStrategyTests {

    @Test
    public void newSessionShouldNotBeCreatedIfNoSessionExistsAndAlwaysCreateIsFalse() throws Exception {
        DefaultAuthenticatedSessionStrategy strategy = new DefaultAuthenticatedSessionStrategy();
        HttpServletRequest request = new MockHttpServletRequest();

        strategy.onAuthentication(mock(Authentication.class), request, new MockHttpServletResponse());

        assertNull(request.getSession(false));
    }

//    @Test
//    public void newSessionIsCreatedIfSessionAlreadyExists() throws Exception {
//        DefaultAuthenticatedSessionStrategy strategy = new DefaultAuthenticatedSessionStrategy();
//        strategy.setSessionRegistry(mock(SessionRegistry.class));
//        HttpServletRequest request = new MockHttpServletRequest();
//        String sessionId = request.getSession().getId();
//
//        strategy.onAuthentication(mock(Authentication.class), request, new MockHttpServletResponse());
//
//        assertFalse(sessionId.equals(request.getSession().getId()));
//    }

    // See SEC-1077
    @Test
    public void onlySavedRequestAttributeIsMigratedIfMigrateAttributesIsFalse() throws Exception {
        DefaultAuthenticatedSessionStrategy strategy = new DefaultAuthenticatedSessionStrategy();
        strategy.setMigrateSessionAttributes(false);
        HttpServletRequest request = new MockHttpServletRequest();
        HttpSession session = request.getSession();
        session.setAttribute("blah", "blah");
        session.setAttribute(SavedRequest.SPRING_SECURITY_SAVED_REQUEST_KEY, "SavedRequest");

        strategy.onAuthentication(mock(Authentication.class), request, new MockHttpServletResponse());

        assertNull(request.getSession().getAttribute("blah"));
        assertNotNull(request.getSession().getAttribute(SavedRequest.SPRING_SECURITY_SAVED_REQUEST_KEY));
    }

    @Test
    public void sessionIsCreatedIfAlwaysCreateTrue() throws Exception {
        DefaultAuthenticatedSessionStrategy strategy = new DefaultAuthenticatedSessionStrategy();
        strategy.setAlwaysCreateSession(true);
        HttpServletRequest request = new MockHttpServletRequest();
        strategy.onAuthentication(mock(Authentication.class), request, new MockHttpServletResponse());
        assertNotNull(request.getSession(false));
    }

}
