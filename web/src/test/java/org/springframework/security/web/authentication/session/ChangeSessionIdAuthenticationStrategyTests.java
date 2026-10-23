/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.web.authentication.session;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.SimpleApplicationEventMulticaster;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionIdChangedEvent;
import org.springframework.security.core.session.SessionRegistryImpl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 *
 */
public class ChangeSessionIdAuthenticationStrategyTests {

	@Test
	public void applySessionFixation() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		String id = request.getSession().getId();
		new ChangeSessionIdAuthenticationStrategy().applySessionFixation(request);
		assertThat(request.getSession().getId()).isNotEqualTo(id);
	}

	@Test
	public void onAuthenticationWhenRegistryHasOldSessionThenMigratesWithoutHttpSessionEventPublisher() {
		// Reproduces gh-19007: without HttpSessionEventPublisher the old session ID used
		// to remain as a ghost entry in the registry after session fixation rotation,
		// causing ConcurrentSessionControlAuthenticationStrategy to count an extra session.
		SessionRegistryImpl registry = new SessionRegistryImpl();
		SimpleApplicationEventMulticaster multicaster = new SimpleApplicationEventMulticaster();
		multicaster.addApplicationListener(registry);
		ChangeSessionIdAuthenticationStrategy strategy = new ChangeSessionIdAuthenticationStrategy();
		strategy.setApplicationEventPublisher((event) -> {
			if (event instanceof ApplicationEvent applicationEvent) {
				multicaster.multicastEvent(applicationEvent);
			}
		});
		MockHttpServletRequest request = new MockHttpServletRequest();
		Object principal = "testPrincipal";
		registry.registerNewSession(request.getSession().getId(), principal);
		strategy.onAuthentication(mock(Authentication.class), request, new MockHttpServletResponse());
		String newSessionId = request.getSession().getId();
		assertThat(registry.getSessionInformation(newSessionId)).isNotNull();
		assertThat(registry.getAllSessions(principal, false)).hasSize(1);
	}

	@Test
	public void onAuthenticationPublishesSessionFixationAndSessionIdChangedEvents() {
		ChangeSessionIdAuthenticationStrategy strategy = new ChangeSessionIdAuthenticationStrategy();
		MockHttpServletRequest request = new MockHttpServletRequest();
		String oldSessionId = request.getSession().getId();
		ApplicationEventPublisher eventPublisher = mock(ApplicationEventPublisher.class);
		strategy.setApplicationEventPublisher(eventPublisher);
		strategy.onAuthentication(mock(Authentication.class), request, new MockHttpServletResponse());
		ArgumentCaptor<ApplicationEvent> captor = ArgumentCaptor.forClass(ApplicationEvent.class);
		verify(eventPublisher, times(2)).publishEvent(captor.capture());
		List<ApplicationEvent> events = captor.getAllValues();
		assertThat(events).hasAtLeastOneElementOfType(SessionFixationProtectionEvent.class);
		SessionIdChangedEvent idChangedEvent = events.stream()
			.filter(SessionIdChangedEvent.class::isInstance)
			.map(SessionIdChangedEvent.class::cast)
			.findFirst()
			.orElseThrow();
		assertThat(idChangedEvent.getOldSessionId()).isEqualTo(oldSessionId);
		assertThat(idChangedEvent.getNewSessionId()).isEqualTo(request.getSession().getId());
		assertThat(idChangedEvent.getNewSessionId()).isNotEqualTo(oldSessionId);
	}

}
