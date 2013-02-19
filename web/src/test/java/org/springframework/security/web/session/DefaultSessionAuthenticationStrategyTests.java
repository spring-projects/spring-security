package org.springframework.security.web.session;

import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.session.SessionFixationProtectionMigrationEvent;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import static org.junit.Assert.*;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

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
        HttpSession session = request.getSession();
        session.setAttribute("blah", "blah");
        session.setAttribute("SPRING_SECURITY_SAVED_REQUEST_KEY", "DefaultSavedRequest");
        String oldSessionId = session.getId();

        // See SEC-2002: Make sure SessionFixationProtectionMigrationEvent is published
        ApplicationEventPublisher eventPublisher = mock(ApplicationEventPublisher.class);
        strategy.setApplicationEventPublisher(eventPublisher);

        Authentication mockAuthentication = mock(Authentication.class);

        strategy.onAuthentication(mockAuthentication, request, new MockHttpServletResponse());

        ArgumentCaptor<ApplicationEvent> eventArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(eventPublisher).publishEvent(eventArgumentCaptor.capture());

        assertFalse(oldSessionId.equals(request.getSession().getId()));
        assertNotNull(request.getSession().getAttribute("blah"));
        assertNotNull(request.getSession().getAttribute("SPRING_SECURITY_SAVED_REQUEST_KEY"));

        // See SEC-2002: Make sure SessionFixationProtectionMigrationEvent is published
        assertNotNull(eventArgumentCaptor.getValue());
        assertTrue(eventArgumentCaptor.getValue() instanceof SessionFixationProtectionMigrationEvent);
        SessionFixationProtectionMigrationEvent event =
                (SessionFixationProtectionMigrationEvent)eventArgumentCaptor.getValue();
        assertEquals(oldSessionId, event.getOldSessionId());
        assertEquals(request.getSession().getId(), event.getNewSessionId());
        assertSame(mockAuthentication, event.getAuthentication());
        assertTrue(event.sessionAttributesWereMigrated());
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
        String oldSessionId = session.getId();

        // See SEC-2002: Make sure SessionFixationProtectionMigrationEvent is published
        ApplicationEventPublisher eventPublisher = mock(ApplicationEventPublisher.class);
        strategy.setApplicationEventPublisher(eventPublisher);

        Authentication mockAuthentication = mock(Authentication.class);

        strategy.onAuthentication(mockAuthentication, request, new MockHttpServletResponse());

        ArgumentCaptor<ApplicationEvent> eventArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(eventPublisher).publishEvent(eventArgumentCaptor.capture());

        assertNull(request.getSession().getAttribute("blah"));
        assertNotNull(request.getSession().getAttribute("SPRING_SECURITY_SAVED_REQUEST_KEY"));

        // See SEC-2002: Make sure SessionFixationProtectionMigrationEvent is published
        assertNotNull(eventArgumentCaptor.getValue());
        assertTrue(eventArgumentCaptor.getValue() instanceof SessionFixationProtectionMigrationEvent);
        SessionFixationProtectionMigrationEvent event =
                (SessionFixationProtectionMigrationEvent)eventArgumentCaptor.getValue();
        assertEquals(oldSessionId, event.getOldSessionId());
        assertEquals(request.getSession().getId(), event.getNewSessionId());
        assertSame(mockAuthentication, event.getAuthentication());
        assertFalse(event.sessionAttributesWereMigrated());
    }

    @Test
    public void sessionIsCreatedIfAlwaysCreateTrue() throws Exception {
        SessionFixationProtectionStrategy strategy = new SessionFixationProtectionStrategy();
        strategy.setAlwaysCreateSession(true);
        HttpServletRequest request = new MockHttpServletRequest();
        strategy.onAuthentication(mock(Authentication.class), request, new MockHttpServletResponse());
        assertNotNull(request.getSession(false));
    }

    // See SEC-2002
    @Test
    public void onSessionChangePublishesMigrationEventIfMigrateAttributesIsTrue() throws Exception {
        SessionFixationProtectionStrategyWithPublicOnSessionChange strategy =
                new SessionFixationProtectionStrategyWithPublicOnSessionChange();
        HttpServletRequest request = new MockHttpServletRequest();
        HttpSession session = request.getSession();

        ApplicationEventPublisher eventPublisher = mock(ApplicationEventPublisher.class);
        strategy.setApplicationEventPublisher(eventPublisher);

        Authentication mockAuthentication = mock(Authentication.class);

        strategy.onSessionChange("oldId01", session, mockAuthentication);

        ArgumentCaptor<ApplicationEvent> eventArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(eventPublisher).publishEvent(eventArgumentCaptor.capture());

        assertNotNull(eventArgumentCaptor.getValue());
        assertTrue(eventArgumentCaptor.getValue() instanceof SessionFixationProtectionMigrationEvent);
        SessionFixationProtectionMigrationEvent event =
                (SessionFixationProtectionMigrationEvent)eventArgumentCaptor.getValue();
        assertEquals("oldId01", event.getOldSessionId());
        assertEquals(request.getSession().getId(), event.getNewSessionId());
        assertSame(mockAuthentication, event.getAuthentication());
        assertTrue(event.sessionAttributesWereMigrated());
    }

    // See SEC-2002
    @Test
    public void onSessionChangePublishesIdChangeEventIfMigrateAttributesIsFalse() throws Exception {
        SessionFixationProtectionStrategyWithPublicOnSessionChange strategy =
                new SessionFixationProtectionStrategyWithPublicOnSessionChange();
        strategy.setMigrateSessionAttributes(false);
        HttpServletRequest request = new MockHttpServletRequest();
        HttpSession session = request.getSession();

        ApplicationEventPublisher eventPublisher = mock(ApplicationEventPublisher.class);
        strategy.setApplicationEventPublisher(eventPublisher);

        Authentication mockAuthentication = mock(Authentication.class);

        strategy.onSessionChange("oldId02", session, mockAuthentication);

        ArgumentCaptor<ApplicationEvent> eventArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(eventPublisher).publishEvent(eventArgumentCaptor.capture());

        assertNotNull(eventArgumentCaptor.getValue());
        assertTrue(eventArgumentCaptor.getValue() instanceof SessionFixationProtectionMigrationEvent);
        SessionFixationProtectionMigrationEvent event =
                (SessionFixationProtectionMigrationEvent)eventArgumentCaptor.getValue();
        assertEquals("oldId02", event.getOldSessionId());
        assertEquals(request.getSession().getId(), event.getNewSessionId());
        assertSame(mockAuthentication, event.getAuthentication());
        assertFalse(event.sessionAttributesWereMigrated());
    }

    // See SEC-2002
    @Test
    public void onSessionChangeDoesNotThrowNullPointerExceptionIfEventPublisherNotSet() throws Exception {
        SessionFixationProtectionStrategyWithPublicOnSessionChange strategy =
                new SessionFixationProtectionStrategyWithPublicOnSessionChange();
        strategy.setMigrateSessionAttributes(false);
        HttpServletRequest request = new MockHttpServletRequest();
        HttpSession session = request.getSession();

        Authentication mockAuthentication = mock(Authentication.class);

        strategy.onSessionChange("oldId03", session, mockAuthentication);
    }

    // See SEC-2002
    private static class SessionFixationProtectionStrategyWithPublicOnSessionChange
            extends SessionFixationProtectionStrategy {
        @Override
        public void onSessionChange(String originalSessionId, HttpSession newSession, Authentication auth) {
            super.onSessionChange(originalSessionId, newSession , auth);
        }
    }
}
