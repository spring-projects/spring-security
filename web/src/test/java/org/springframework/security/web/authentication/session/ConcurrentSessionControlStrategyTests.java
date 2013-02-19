package org.springframework.security.web.authentication.session;

import static org.junit.Assert.*;
import static org.mockito.AdditionalMatchers.not;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

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
import org.springframework.security.core.session.SessionRegistry;

/**
 *
 * @author Rob Winch
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class ConcurrentSessionControlStrategyTests {
    @Mock
    private SessionRegistry sessionRegistry;
    @Mock
    private Authentication authentication;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    private ConcurrentSessionControlStrategy strategy;

    @Before
    public void setup() throws Exception {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();

        strategy = new ConcurrentSessionControlStrategy(sessionRegistry);
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

        // See SEC-2002: Make sure SessionIdChangedEvent or subclass is published
        ApplicationEventPublisher eventPublisher = mock(ApplicationEventPublisher.class);
        strategy.setApplicationEventPublisher(eventPublisher);

        strategy.onAuthentication(authentication, request, response);

        verify(sessionRegistry,times(0)).removeSessionInformation(anyString());
        verify(sessionRegistry).registerNewSession(not(eq(originalSessionId)), anyObject());

        ArgumentCaptor<ApplicationEvent> eventArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(eventPublisher).publishEvent(eventArgumentCaptor.capture());

        // See SEC-2002: Make sure SessionIdChangedEvent or subclass is published
        assertNotNull(eventArgumentCaptor.getValue());
        assertTrue(eventArgumentCaptor.getValue() instanceof SessionIdChangedEvent);
        SessionIdChangedEvent event = (SessionIdChangedEvent)eventArgumentCaptor.getValue();
        assertEquals(originalSessionId, event.getOldSessionId());
        assertEquals(request.getSession().getId(), event.getNewSessionId());
        assertSame(authentication, event.getAuthentication());
    }
}
