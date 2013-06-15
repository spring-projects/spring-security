package org.springframework.security.web.authentication.session;

import static org.junit.Assert.*;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;

import javax.servlet.http.HttpSession;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.support.BeanDefinitionValidationException;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.Authentication;

/**
 * @author Nicholas Williams
 */
public class SessionFixationProtectionSchemeStrategyTests {

    private Authentication authentication;

    private MockHttpServletRequest request;

    private MockHttpServletResponse response;

    private SessionFixationProtectionSchemeStrategy strategy;

    @Before
    public void setUp() {
        this.authentication = mock(Authentication.class);
        this.request = new MockHttpServletRequest();
        this.response = new MockHttpServletResponse();
        this.strategy = new SessionFixationProtectionSchemeStrategy();
    }

    @Test
    public void newSessionShouldNotBeCreatedIfNoSessionExistsAndAlwaysCreateIsFalse() {
        this.strategy.onAuthentication(this.authentication, this.request, this.response);

        assertNull("A session should not have been created.", this.request.getSession(false));
    }

    @Test
    public void newSessionShouldBeCreatedIfNoSessionExistsAndAlwaysCreateIsTrue() {
        this.strategy.setAlwaysCreateSession(true);
        this.strategy.onAuthentication(this.authentication, this.request, this.response);

        assertNotNull("A session should have been created.", this.request.getSession(false));
    }

    @Test
    public void noSessionFixationAppliedIfRequestedSessionIdNotValid() {
        this.request.setRequestedSessionIdValid(false);
        String sessionId = this.request.getSession().getId();

        this.strategy.onAuthentication(this.authentication, this.request, this.response);

        assertEquals("The session ID should not have changed.", sessionId, this.request.getSession().getId());
    }

    @Test
    public void noSessionFixationAppliedIfSchemeIsNone() {
        String sessionId = this.request.getSession().getId();

        this.strategy.setSessionFixationProtectionScheme(SessionFixationProtectionScheme.NONE);
        this.strategy.onAuthentication(this.authentication, this.request, this.response);

        assertEquals("The session ID should not have changed.", sessionId, this.request.getSession().getId());
    }

    @Test
    public void newSessionAndOnlySpringAttributesMigratedIfSchemeIsNewSession() {
        HttpSession originalSession = this.request.getSession();
        assert originalSession instanceof MockHttpSession;
        String oldSessionId = originalSession.getId();

        originalSession.setAttribute("testAttribute1", "hello");
        originalSession.setAttribute("SPRING_FRAMEWORK_ATTR", "nope");
        originalSession.setAttribute("SPRING_SECURITY_TEST", "value1");
        originalSession.setAttribute("SPRING_SECURITY_ANOTHER", "anotherValue2");

        this.strategy.setSessionFixationProtectionScheme(SessionFixationProtectionScheme.NEW_SESSION);
        this.strategy.onAuthentication(this.authentication, this.request, this.response);

        HttpSession newSession = this.request.getSession(false);
        assertNotNull("The new session should not be null.", newSession);
        assertNotSame("The new session should be different.", originalSession, newSession);
        assertFalse("The new session should have a different ID.", oldSessionId.equals(newSession.getId()));

        assertTrue("The original session should have been invalidated.", ((MockHttpSession) originalSession).isInvalid());

        assertNull("testAttribute1 should not exist.", newSession.getAttribute("testAttribute1"));
        assertNull("SPRING_FRAMEWORK_ATTR should not exist.", newSession.getAttribute("SPRING_FRAMEWORK_ATTR"));
        assertEquals("SPRING_SECURITY_TEST is not correct.", "value1", newSession.getAttribute("SPRING_SECURITY_TEST"));
        assertEquals("SPRING_SECURITY_ANOTHER is not correct.", "anotherValue2", newSession.getAttribute("SPRING_SECURITY_ANOTHER"));
    }

    @Test
    public void newSessionAndAllAttributesMigratedIfSchemeIsMigrateSession() {
        HttpSession originalSession = this.request.getSession();
        assert originalSession instanceof MockHttpSession;
        String oldSessionId = originalSession.getId();

        originalSession.setAttribute("testAttribute1", "hello");
        originalSession.setAttribute("SPRING_FRAMEWORK_ATTR", "nope");
        originalSession.setAttribute("SPRING_SECURITY_TEST", "value1");
        originalSession.setAttribute("SPRING_SECURITY_ANOTHER", "anotherValue2");

        this.strategy.setSessionFixationProtectionScheme(SessionFixationProtectionScheme.MIGRATE_SESSION);
        this.strategy.onAuthentication(this.authentication, this.request, this.response);

        HttpSession newSession = this.request.getSession(false);
        assertNotNull("The new session should not be null.", newSession);
        assertNotSame("The new session should be different.", originalSession, newSession);
        assertFalse("The new session should have a different ID.", oldSessionId.equals(newSession.getId()));

        assertTrue("The original session should have been invalidated.", ((MockHttpSession) originalSession).isInvalid());

        assertEquals("testAttribute1 is not correct.", "hello", newSession.getAttribute("testAttribute1"));
        assertEquals("SPRING_FRAMEWORK_ATTR is not correct.", "nope", newSession.getAttribute("SPRING_FRAMEWORK_ATTR"));
        assertEquals("SPRING_SECURITY_TEST is not correct.", "value1", newSession.getAttribute("SPRING_SECURITY_TEST"));
        assertEquals("SPRING_SECURITY_ANOTHER is not correct.", "anotherValue2", newSession.getAttribute("SPRING_SECURITY_ANOTHER"));
    }

    @Test
    public void onAuthenticationFailsWithIllegalStateExceptionIfSchemeIsChangeSessionIdBecauseServlet31NotOnClasspath() {
        HttpSession originalSession = this.request.getSession();
        assert originalSession != null;

        this.strategy.setSessionFixationProtectionScheme(SessionFixationProtectionScheme.CHANGE_SESSION_ID);

        try {
            this.strategy.onAuthentication(this.authentication, this.request, this.response);
            fail("Expected IllegalStateException, got no exception.");
        }
        catch (IllegalStateException e) {
            // good
        }
    }

    @Test(expected = BeanDefinitionValidationException.class)
    public void checkSchemeValidForContextIfSchemeIsChangeSessionIfFailsWithExceptionBecauseServlet31NotOnClasspath() {
        SessionFixationProtectionScheme.CHANGE_SESSION_ID.checkSchemeValidForContext();
    }

    @Test
    public void newSessionShouldBeCreatedAndNoEventPublishedIfNoSessionExistsAndAlwaysCreateIsTrue() {
        ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);
        this.strategy.setApplicationEventPublisher(publisher);

        this.strategy.setAlwaysCreateSession(true);
        this.strategy.onAuthentication(this.authentication, this.request, this.response);

        assertNotNull("A session should have been created.", this.request.getSession(false));

        verifyZeroInteractions(publisher);
    }

    @Test
    public void noSessionFixationAppliedAndNoEventPublishedIfRequestedSessionIdNotValid() {
        ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);
        this.strategy.setApplicationEventPublisher(publisher);

        this.request.setRequestedSessionIdValid(false);
        String sessionId = this.request.getSession().getId();

        this.strategy.onAuthentication(this.authentication, this.request, this.response);

        assertEquals("The session ID should not have changed.", sessionId, this.request.getSession().getId());

        verifyZeroInteractions(publisher);
    }

    @Test
    public void noSessionFixationAppliedAndNoEventPublishedIfSchemeIsNone() {
        ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);
        this.strategy.setApplicationEventPublisher(publisher);

        String sessionId = this.request.getSession().getId();

        this.strategy.setSessionFixationProtectionScheme(SessionFixationProtectionScheme.NONE);
        this.strategy.onAuthentication(this.authentication, this.request, this.response);

        assertEquals("The session ID should not have changed.", sessionId, this.request.getSession().getId());

        verifyZeroInteractions(publisher);
    }

    @Test
    public void newSessionAndOnlySpringAttributesMigratedAndEventPublishedIfSchemeIsNewSession() {
        ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);
        this.strategy.setApplicationEventPublisher(publisher);

        HttpSession originalSession = this.request.getSession();
        assert originalSession instanceof MockHttpSession;
        String oldSessionId = originalSession.getId();

        originalSession.setAttribute("testAttribute1", "hello");
        originalSession.setAttribute("SPRING_FRAMEWORK_ATTR", "nope");
        originalSession.setAttribute("SPRING_SECURITY_TEST", "value1");
        originalSession.setAttribute("SPRING_SECURITY_ANOTHER", "anotherValue2");

        this.strategy.setSessionFixationProtectionScheme(SessionFixationProtectionScheme.NEW_SESSION);
        this.strategy.onAuthentication(this.authentication, this.request, this.response);

        HttpSession newSession = this.request.getSession(false);
        assertNotNull("The new session should not be null.", newSession);
        assertNotSame("The new session should be different.", originalSession, newSession);
        assertFalse("The new session should have a different ID.", oldSessionId.equals(newSession.getId()));

        assertTrue("The original session should have been invalidated.", ((MockHttpSession) originalSession).isInvalid());

        assertNull("testAttribute1 should not exist.", newSession.getAttribute("testAttribute1"));
        assertNull("SPRING_FRAMEWORK_ATTR should not exist.", newSession.getAttribute("SPRING_FRAMEWORK_ATTR"));
        assertEquals("SPRING_SECURITY_TEST is not correct.", "value1", newSession.getAttribute("SPRING_SECURITY_TEST"));
        assertEquals("SPRING_SECURITY_ANOTHER is not correct.", "anotherValue2", newSession.getAttribute("SPRING_SECURITY_ANOTHER"));

        ArgumentCaptor<ApplicationEvent> eventArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(publisher).publishEvent(eventArgumentCaptor.capture());
        assertNotNull(eventArgumentCaptor.getValue());
        assertTrue(eventArgumentCaptor.getValue() instanceof SessionFixationProtectionEvent);
        SessionFixationProtectionEvent event = (SessionFixationProtectionEvent)eventArgumentCaptor.getValue();
        assertEquals(oldSessionId, event.getOldSessionId());
        assertEquals(newSession.getId(), event.getNewSessionId());
        assertSame(this.authentication, event.getAuthentication());
    }

    @Test
    public void newSessionAndAllAttributesMigratedAndEventPublishedIfSchemeIsMigrateSession() {
        ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);
        this.strategy.setApplicationEventPublisher(publisher);

        HttpSession originalSession = this.request.getSession();
        assert originalSession instanceof MockHttpSession;
        String oldSessionId = originalSession.getId();

        originalSession.setAttribute("testAttribute1", "hello");
        originalSession.setAttribute("SPRING_FRAMEWORK_ATTR", "nope");
        originalSession.setAttribute("SPRING_SECURITY_TEST", "value1");
        originalSession.setAttribute("SPRING_SECURITY_ANOTHER", "anotherValue2");

        this.strategy.setSessionFixationProtectionScheme(SessionFixationProtectionScheme.MIGRATE_SESSION);
        this.strategy.onAuthentication(this.authentication, this.request, this.response);

        HttpSession newSession = this.request.getSession(false);
        assertNotNull("The new session should not be null.", newSession);
        assertNotSame("The new session should be different.", originalSession, newSession);
        assertFalse("The new session should have a different ID.", oldSessionId.equals(newSession.getId()));

        assertTrue("The original session should have been invalidated.", ((MockHttpSession) originalSession).isInvalid());

        assertEquals("testAttribute1 is not correct.", "hello", newSession.getAttribute("testAttribute1"));
        assertEquals("SPRING_FRAMEWORK_ATTR is not correct.", "nope", newSession.getAttribute("SPRING_FRAMEWORK_ATTR"));
        assertEquals("SPRING_SECURITY_TEST is not correct.", "value1", newSession.getAttribute("SPRING_SECURITY_TEST"));
        assertEquals("SPRING_SECURITY_ANOTHER is not correct.", "anotherValue2", newSession.getAttribute("SPRING_SECURITY_ANOTHER"));

        ArgumentCaptor<ApplicationEvent> eventArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(publisher).publishEvent(eventArgumentCaptor.capture());
        assertNotNull(eventArgumentCaptor.getValue());
        assertTrue(eventArgumentCaptor.getValue() instanceof SessionFixationProtectionEvent);
        SessionFixationProtectionEvent event = (SessionFixationProtectionEvent)eventArgumentCaptor.getValue();
        assertEquals(oldSessionId, event.getOldSessionId());
        assertEquals(newSession.getId(), event.getNewSessionId());
        assertSame(this.authentication, event.getAuthentication());
    }
}
