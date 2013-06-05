/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.authentication.session;

import static org.junit.Assert.*;
import static org.mockito.AdditionalMatchers.not;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

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

        strategy.onAuthentication(authentication, request, response);

        verify(sessionRegistry,times(0)).removeSessionInformation(anyString());
        verify(sessionRegistry).registerNewSession(not(eq(originalSessionId)), anyObject());
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
}
