/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.session;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.session.SessionFixationProtectionEvent;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;

/**
 *
 * @author Luke Taylor
 */
public class DefaultSessionAuthenticationStrategyTests {

    @Test
    public void newSessionShouldNotBeCreatedIfNoSessionExistsAndAlwaysCreateIsFalse() throws Exception {
        SessionFixationProtectionStrategy strategy = new SessionFixationProtectionStrategy();
        HttpServletRequest request = new MockHttpServletRequest();

        strategy.onAuthentication(mock(Authentication.class), request, new MockHttpServletResponse());

        assertNull(request.getSession(false));
    }

    @Test
    public void newSessionIsCreatedIfSessionAlreadyExists() throws Exception {
        SessionFixationProtectionStrategy strategy = new SessionFixationProtectionStrategy();
        HttpServletRequest request = new MockHttpServletRequest();
        String sessionId = request.getSession().getId();

        strategy.onAuthentication(mock(Authentication.class), request, new MockHttpServletResponse());

        assertFalse(sessionId.equals(request.getSession().getId()));
    }

    // SEC-2002
    @Test
    public void newSessionIsCreatedIfSessionAlreadyExistsWithEventPublisher() throws Exception {
        SessionFixationProtectionStrategy strategy = new SessionFixationProtectionStrategy();
        HttpServletRequest request = new MockHttpServletRequest();
        HttpSession session = request.getSession();
        session.setAttribute("blah", "blah");
        session.setAttribute("SPRING_SECURITY_SAVED_REQUEST_KEY", "DefaultSavedRequest");
        String oldSessionId = session.getId();

        ApplicationEventPublisher eventPublisher = mock(ApplicationEventPublisher.class);
        strategy.setApplicationEventPublisher(eventPublisher);

        Authentication mockAuthentication = mock(Authentication.class);

        strategy.onAuthentication(mockAuthentication, request, new MockHttpServletResponse());

        ArgumentCaptor<ApplicationEvent> eventArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(eventPublisher).publishEvent(eventArgumentCaptor.capture());

        assertFalse(oldSessionId.equals(request.getSession().getId()));
        assertNotNull(request.getSession().getAttribute("blah"));
        assertNotNull(request.getSession().getAttribute("SPRING_SECURITY_SAVED_REQUEST_KEY"));

        assertNotNull(eventArgumentCaptor.getValue());
        assertTrue(eventArgumentCaptor.getValue() instanceof SessionFixationProtectionEvent);
        SessionFixationProtectionEvent event = (SessionFixationProtectionEvent)eventArgumentCaptor.getValue();
        assertEquals(oldSessionId, event.getOldSessionId());
        assertEquals(request.getSession().getId(), event.getNewSessionId());
        assertSame(mockAuthentication, event.getAuthentication());
    }

    // See SEC-1077
    @Test
    public void onlySavedRequestAttributeIsMigratedIfMigrateAttributesIsFalse() throws Exception {
        SessionFixationProtectionStrategy strategy = new SessionFixationProtectionStrategy();
        strategy.setMigrateSessionAttributes(false);
        HttpServletRequest request = new MockHttpServletRequest();
        HttpSession session = request.getSession();
        session.setAttribute("blah", "blah");
        session.setAttribute("SPRING_SECURITY_SAVED_REQUEST_KEY", "DefaultSavedRequest");

        strategy.onAuthentication(mock(Authentication.class), request, new MockHttpServletResponse());

        assertNull(request.getSession().getAttribute("blah"));
        assertNotNull(request.getSession().getAttribute("SPRING_SECURITY_SAVED_REQUEST_KEY"));
    }

    // SEC-2002
    @Test
    public void onlySavedRequestAttributeIsMigratedIfMigrateAttributesIsFalseWithEventPublisher() throws Exception {
        SessionFixationProtectionStrategy strategy = new SessionFixationProtectionStrategy();
        strategy.setMigrateSessionAttributes(false);
        HttpServletRequest request = new MockHttpServletRequest();
        HttpSession session = request.getSession();
        session.setAttribute("blah", "blah");
        session.setAttribute("SPRING_SECURITY_SAVED_REQUEST_KEY", "DefaultSavedRequest");
        String oldSessionId = session.getId();

        ApplicationEventPublisher eventPublisher = mock(ApplicationEventPublisher.class);
        strategy.setApplicationEventPublisher(eventPublisher);

        Authentication mockAuthentication = mock(Authentication.class);

        strategy.onAuthentication(mockAuthentication, request, new MockHttpServletResponse());

        ArgumentCaptor<ApplicationEvent> eventArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(eventPublisher).publishEvent(eventArgumentCaptor.capture());

        assertNull(request.getSession().getAttribute("blah"));
        assertNotNull(request.getSession().getAttribute("SPRING_SECURITY_SAVED_REQUEST_KEY"));

        assertNotNull(eventArgumentCaptor.getValue());
        assertTrue(eventArgumentCaptor.getValue() instanceof SessionFixationProtectionEvent);
        SessionFixationProtectionEvent event = (SessionFixationProtectionEvent)eventArgumentCaptor.getValue();
        assertEquals(oldSessionId, event.getOldSessionId());
        assertEquals(request.getSession().getId(), event.getNewSessionId());
        assertSame(mockAuthentication, event.getAuthentication());
    }

    @Test
    public void sessionIsCreatedIfAlwaysCreateTrue() throws Exception {
        SessionFixationProtectionStrategy strategy = new SessionFixationProtectionStrategy();
        strategy.setAlwaysCreateSession(true);
        HttpServletRequest request = new MockHttpServletRequest();
        strategy.onAuthentication(mock(Authentication.class), request, new MockHttpServletResponse());
        assertNotNull(request.getSession(false));
    }

}
