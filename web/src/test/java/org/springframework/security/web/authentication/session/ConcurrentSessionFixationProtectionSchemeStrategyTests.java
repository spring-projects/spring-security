package org.springframework.security.web.authentication.session;

import static org.junit.Assert.*;
import static org.mockito.AdditionalMatchers.not;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.same;

import java.util.Arrays;
import java.util.Date;

import javax.servlet.http.HttpSession;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;

/**
 * @author Nicholas Williams
 * @author Rob Winch
 */
@RunWith(MockitoJUnitRunner.class)
public class ConcurrentSessionFixationProtectionSchemeStrategyTests {

    @Mock
    private SessionRegistry sessionRegistry;
    @Mock
    private Authentication authentication;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    private ConcurrentSessionFixationProtectionSchemeStrategy strategy;

    @Before
    public void setup() throws Exception {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();

        strategy = new ConcurrentSessionFixationProtectionSchemeStrategy(sessionRegistry);
    }

    @Test
    public void onAuthenticationNewSession() {
        strategy.onAuthentication(authentication, request, response);

        verify(sessionRegistry,times(0)).removeSessionInformation(anyString());
        verify(sessionRegistry).registerNewSession(anyString(), anyObject());
    }

    // SEC-1875
    @Test
    public void onAuthenticationChangeSession() {
        String originalSessionId = request.getSession().getId();

        strategy.onAuthentication(authentication, request, response);

        verify(sessionRegistry,times(0)).removeSessionInformation(anyString());
        verify(sessionRegistry).registerNewSession(not(eq(originalSessionId)), anyObject());
    }

    @Test
    public void onAuthenticationNoExceptionIfMaximumExceededDefaultThresholdOf1() throws Exception {
        strategy.setSessionFixationProtectionScheme(SessionFixationProtectionScheme.NONE);

        HttpSession session = request.getSession();

        Object principal = new Object();

        SessionInformation session1 = new SessionInformation(principal, session.getId(), new Date(1234567890L));
        SessionInformation session2 = new SessionInformation(principal, "abc123", new Date(2345678901L));

        when(authentication.getPrincipal()).thenReturn(principal, principal);
        when(sessionRegistry.getAllSessions(same(principal), eq(false)))
                .thenReturn(Arrays.asList(session1))
                .thenReturn(Arrays.asList(session1, session2));

        strategy.onAuthentication(authentication, request, response);

        assertFalse("The first session should not be invalid yet.", session1.isExpired());
        assertFalse("The second session should not be invalid.", session2.isExpired());

        strategy.onAuthentication(authentication, request, response);

        assertFalse("The second session should still not be invalid.", session2.isExpired());
        assertTrue("The first session should be invalid now.", session1.isExpired());
    }

    @Test
    public void onAuthenticationNoExceptionIfMaximumExceededThresholdOf3() throws Exception {
        strategy.setSessionFixationProtectionScheme(SessionFixationProtectionScheme.NONE);
        strategy.setMaximumSessions(3);

        HttpSession session = request.getSession();

        Object principal = new Object();

        SessionInformation session1 = new SessionInformation(principal, session.getId(), new Date(1234567890L));
        SessionInformation session2 = new SessionInformation(principal, "abc123", new Date(2345678901L));
        SessionInformation session3 = new SessionInformation(principal, "123abc", new Date(3456789012L));
        SessionInformation session4 = new SessionInformation(principal, "a1b2c3", new Date(4567890123L));

        when(authentication.getPrincipal()).thenReturn(principal, principal, principal, principal);
        when(sessionRegistry.getAllSessions(same(principal), eq(false)))
                .thenReturn(Arrays.asList(session1))
                .thenReturn(Arrays.asList(session1, session2))
                .thenReturn(Arrays.asList(session1, session2, session3))
                .thenReturn(Arrays.asList(session1, session2, session3, session4));

        strategy.onAuthentication(authentication, request, response);

        assertFalse("The first session should not be invalid yet.", session1.isExpired());
        assertFalse("The second session should not be invalid.", session2.isExpired());
        assertFalse("The third session should not be invalid.", session3.isExpired());
        assertFalse("The fourth session should not be invalid.", session4.isExpired());

        strategy.onAuthentication(authentication, request, response);

        assertFalse("The first session should still not be invalid.", session1.isExpired());
        assertFalse("The second session should still not be invalid.", session2.isExpired());
        assertFalse("The third session should still not be invalid.", session3.isExpired());
        assertFalse("The fourth session should still not be invalid.", session4.isExpired());

        strategy.onAuthentication(authentication, request, response);

        assertFalse("The first session should yet again still not be invalid.", session1.isExpired());
        assertFalse("The second session should yet again still not be invalid.", session2.isExpired());
        assertFalse("The third session should yet again still not be invalid.", session3.isExpired());
        assertFalse("The fourth session should yet again still not be invalid.", session4.isExpired());

        strategy.onAuthentication(authentication, request, response);

        assertFalse("The second session should not be invalid at the end.", session2.isExpired());
        assertFalse("The third session should not be invalid at the end.", session3.isExpired());
        assertFalse("The fourth session should not be invalid at the end.", session4.isExpired());
        assertTrue("The first session should be invalid now.", session1.isExpired());
    }

    @Test
    public void onAuthenticationExceptionIfMaximumExceededDefaultThresholdOf1() throws Exception {
        strategy.setSessionFixationProtectionScheme(SessionFixationProtectionScheme.NONE);
        strategy.setExceptionIfMaximumExceeded(true);

        HttpSession session = request.getSession();

        Object principal = new Object();

        SessionInformation session1 = new SessionInformation(principal, session.getId(), new Date(1234567890L));
        SessionInformation session2 = new SessionInformation(principal, "abc123", new Date(2345678901L));

        when(authentication.getPrincipal()).thenReturn(principal, principal);
        when(sessionRegistry.getAllSessions(same(principal), eq(false)))
                .thenReturn(Arrays.asList(session1))
                .thenReturn(Arrays.asList(session1, session2));

        strategy.onAuthentication(authentication, request, response);

        assertFalse("The first session should not be invalid yet.", session1.isExpired());
        assertFalse("The second session should not be invalid.", session2.isExpired());

        try {
            strategy.onAuthentication(authentication, request, response);
            fail("Expected SessionAuthenticationException, got no exception.");
        }
        catch (SessionAuthenticationException e) {
            assertFalse("The first session should not be invalid in the catch block.", session1.isExpired());
        }
    }

    @Test
    public void onAuthenticationExceptionIfMaximumExceededThresholdOf3() throws Exception {
        strategy.setSessionFixationProtectionScheme(SessionFixationProtectionScheme.NONE);
        strategy.setExceptionIfMaximumExceeded(true);
        strategy.setMaximumSessions(3);

        HttpSession session = request.getSession();

        Object principal = new Object();

        SessionInformation session1 = new SessionInformation(principal, session.getId(), new Date(1234567890L));
        SessionInformation session2 = new SessionInformation(principal, "abc123", new Date(2345678901L));
        SessionInformation session3 = new SessionInformation(principal, "123abc", new Date(3456789012L));
        SessionInformation session4 = new SessionInformation(principal, "a1b2c3", new Date(4567890123L));

        when(authentication.getPrincipal()).thenReturn(principal, principal, principal, principal);
        when(sessionRegistry.getAllSessions(same(principal), eq(false)))
                .thenReturn(Arrays.asList(session1))
                .thenReturn(Arrays.asList(session1, session2))
                .thenReturn(Arrays.asList(session1, session2, session3))
                .thenReturn(Arrays.asList(session1, session2, session3, session4));

        strategy.onAuthentication(authentication, request, response);

        assertFalse("The first session should not be invalid yet.", session1.isExpired());
        assertFalse("The second session should not be invalid.", session2.isExpired());
        assertFalse("The third session should not be invalid.", session3.isExpired());
        assertFalse("The fourth session should not be invalid.", session4.isExpired());

        strategy.onAuthentication(authentication, request, response);

        assertFalse("The first session should still not be invalid.", session1.isExpired());
        assertFalse("The second session should still not be invalid.", session2.isExpired());
        assertFalse("The third session should still not be invalid.", session3.isExpired());
        assertFalse("The fourth session should still not be invalid.", session4.isExpired());

        strategy.onAuthentication(authentication, request, response);

        assertFalse("The first session should yet again still not be invalid.", session1.isExpired());
        assertFalse("The second session should yet again still not be invalid.", session2.isExpired());
        assertFalse("The third session should yet again still not be invalid.", session3.isExpired());
        assertFalse("The fourth session should yet again still not be invalid.", session4.isExpired());

        try {
            strategy.onAuthentication(authentication, request, response);
            fail("Expected SessionAuthenticationException, got no exception.");
        }
        catch (SessionAuthenticationException e) {
            assertFalse("The first session should not be invalid in the catch block.", session1.isExpired());
            assertFalse("The second session should not be invalid in the catch block.", session2.isExpired());
            assertFalse("The third session should not be invalid in the catch block.", session3.isExpired());
        }
    }

    // SEC-2002
    @Test
    public void onAuthenticationChangeSessionWithEventPublisher() {
        String originalSessionId = request.getSession().getId();

        ApplicationEventPublisher eventPublisher = mock(ApplicationEventPublisher.class);
        strategy.setApplicationEventPublisher(eventPublisher);

        strategy.onAuthentication(authentication, request, response);

        verify(sessionRegistry,times(0)).removeSessionInformation(anyString());
        verify(sessionRegistry).registerNewSession(not(eq(originalSessionId)), anyObject());

        ArgumentCaptor<ApplicationEvent> eventArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(eventPublisher).publishEvent(eventArgumentCaptor.capture());

        assertNotNull(eventArgumentCaptor.getValue());
        assertTrue(eventArgumentCaptor.getValue() instanceof SessionFixationProtectionEvent);
        SessionFixationProtectionEvent event = (SessionFixationProtectionEvent)eventArgumentCaptor.getValue();
        assertEquals(originalSessionId, event.getOldSessionId());
        assertEquals(request.getSession().getId(), event.getNewSessionId());
        assertSame(authentication, event.getAuthentication());
    }

    @Test(expected=IllegalArgumentException.class)
    public void setApplicationEventPublisherForbidsNulls() {
        strategy.setApplicationEventPublisher(null);
    }

    @Test
    public void onAuthenticationNoExceptionWhenRequireApplicationEventPublisherSet() {
        strategy.onAuthentication(authentication, request, response);
    }
}
