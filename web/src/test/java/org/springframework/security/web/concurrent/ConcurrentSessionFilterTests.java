/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.web.concurrent;

import java.util.Date;
import javax.servlet.FilterChain;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessEvent;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.session.ConcurrentSessionFilter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Tests {@link ConcurrentSessionFilter}.
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
public class ConcurrentSessionFilterTests {

	@Before
	public void setup() {
		SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("test", "test"));
	}

	@After
	public void cleanUp() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void detectsExpiredSessions() throws Exception {
		// Setup our HTTP request
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpSession session = new MockHttpSession();
		request.setSession(session);

		MockHttpServletResponse response = new MockHttpServletResponse();

		SessionRegistry registry = new SessionRegistryImpl();
		registry.registerNewSession(session.getId(), "principal");
		registry.getSessionInformation(session.getId()).expireNow();

		ApplicationEventPublisher eventPublisher = mock(ApplicationEventPublisher.class);
		ArgumentCaptor<LogoutSuccessEvent> captor = ArgumentCaptor.forClass(LogoutSuccessEvent.class);

		// Setup our test fixture and registry to want this session to be expired
		ConcurrentSessionFilter filter = new ConcurrentSessionFilter(registry,
				"/expired.jsp");
		filter.setRedirectStrategy(new DefaultRedirectStrategy());
		filter.setLogoutHandlers(new LogoutHandler[] { new SecurityContextLogoutHandler() });
		filter.setApplicationEventPublisher(eventPublisher);
		filter.afterPropertiesSet();

		FilterChain fc = mock(FilterChain.class);
		filter.doFilter(request, response, fc);
		// Expect that the filter chain will not be invoked, as we redirect to expiredUrl
		verifyZeroInteractions(fc);

		verify(eventPublisher, times(1)).publishEvent(captor.capture());
		LogoutSuccessEvent event = captor.getValue();
		assertThat(event.wasForcedLogout()).isTrue();

		assertThat(response.getRedirectedUrl()).isEqualTo("/expired.jsp");
	}

	// As above, but with no expiredUrl set.
	@Test
	public void returnsExpectedMessageWhenNoExpiredUrlSet() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpSession session = new MockHttpSession();
		request.setSession(session);

		MockHttpServletResponse response = new MockHttpServletResponse();

		SessionRegistry registry = new SessionRegistryImpl();
		registry.registerNewSession(session.getId(), "principal");
		registry.getSessionInformation(session.getId()).expireNow();

		ApplicationEventPublisher eventPublisher = mock(ApplicationEventPublisher.class);
		ArgumentCaptor<LogoutSuccessEvent> captor = ArgumentCaptor.forClass(LogoutSuccessEvent.class);


		ConcurrentSessionFilter filter = new ConcurrentSessionFilter(registry);
		filter.setApplicationEventPublisher(eventPublisher);
		filter.afterPropertiesSet();

		FilterChain fc = mock(FilterChain.class);
		filter.doFilter(request, response, fc);
		verifyZeroInteractions(fc);

		verify(eventPublisher, times(1)).publishEvent(captor.capture());
		LogoutSuccessEvent event = captor.getValue();
		assertThat(event.wasForcedLogout()).isTrue();

		assertThat(response.getContentAsString()).isEqualTo("This session has been expired (possibly due to multiple concurrent logins being "
						+ "attempted as the same user).");
	}

	@Test(expected = IllegalArgumentException.class)
	public void detectsMissingSessionRegistry() throws Exception {
		new ConcurrentSessionFilter(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void detectsInvalidUrl() throws Exception {
		new ConcurrentSessionFilter(new SessionRegistryImpl(), "ImNotValid");
	}

	@Test
	public void lastRequestTimeUpdatesCorrectly() throws Exception {
		// Setup our HTTP request
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpSession session = new MockHttpSession();
		request.setSession(session);

		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain fc = mock(FilterChain.class);

		// Setup our test fixture
		SessionRegistry registry = new SessionRegistryImpl();
		registry.registerNewSession(session.getId(), "principal");
		ConcurrentSessionFilter filter = new ConcurrentSessionFilter(registry,
				"/expired.jsp");

		Date lastRequest = registry.getSessionInformation(session.getId())
				.getLastRequest();

		Thread.sleep(1000);

		filter.doFilter(request, response, fc);

		verify(fc).doFilter(request, response);
		assertThat(registry.getSessionInformation(session.getId()).getLastRequest().after(lastRequest)).isTrue();
	}
}
