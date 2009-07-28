package org.springframework.security.web.session;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

import javax.servlet.http.HttpServletRequest;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;

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

        strategy.onAuthenticationSuccess(mock(Authentication.class), request, new MockHttpServletResponse());

        assertNull(request.getSession(false));
    }

    @Test
    public void newSessionIsCreatedIfSessionAlreadyExists() throws Exception {
        DefaultAuthenticatedSessionStrategy strategy = new DefaultAuthenticatedSessionStrategy();
        HttpServletRequest request = new MockHttpServletRequest();
        String sessionId = request.getSession().getId();

        strategy.onAuthenticationSuccess(mock(Authentication.class), request, new MockHttpServletResponse());

        assertFalse(sessionId.equals(request.getSession().getId()));
    }

}
