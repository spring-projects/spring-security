/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.web.authentication.logout;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * @author Marten Deinum
 */
public class LogoutFilterTest {

	private static final Authentication TEST_AUTH =new TestingAuthenticationToken("test", "test");

	@Before
	public void setup() {
		SecurityContextHolder.getContext().setAuthentication(TEST_AUTH);
	}

	@After
	public void cleanUp() {
		SecurityContextHolder.clearContext();
	}

		@Test(expected = IllegalArgumentException.class)
	public void detectsMissingLogoutSuccessHandler() {
		new LogoutFilter((LogoutSuccessHandler) null, new TestLogoutHandler());
	}

	@Test(expected = IllegalArgumentException.class)
	public void detectsInvalidUrl() {
		new LogoutFilter("ImNotValid", new TestLogoutHandler());
	}

	@Test(expected = IllegalArgumentException.class)
	public void detectsEmptyLogoutHandlersWhenUsingUrl() {
		new LogoutFilter("/logout");
	}

	@Test(expected = IllegalArgumentException.class)
	public void detectsEmptyLogoutHandlersWhenUsingLogoutSuccessHandler() {
		new LogoutFilter(new SimpleUrlLogoutSuccessHandler());
	}

	@Test
	public void handleLogoutAndFireAnEvent() throws Exception {

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setPathInfo("/logout");
		MockHttpSession session = new MockHttpSession();
		request.setSession(session);

		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain fc = mock(FilterChain.class);

		LogoutSuccessHandler logoutSuccessHandler = mock(LogoutSuccessHandler.class);
		LogoutHandler logoutHandler = mock(LogoutHandler.class);
		ApplicationEventPublisher eventPublisher = mock(ApplicationEventPublisher.class);
		ArgumentCaptor<LogoutSuccessEvent> captor = ArgumentCaptor.forClass(LogoutSuccessEvent.class);

		LogoutFilter filter = new LogoutFilter(logoutSuccessHandler, logoutHandler);
		filter.setApplicationEventPublisher(eventPublisher);
		filter.afterPropertiesSet();

		filter.doFilter(request, response, fc);

		verifyZeroInteractions(fc);
		verify(logoutHandler, times(1)).logout(request, response, TEST_AUTH);
		verify(logoutSuccessHandler, times(1)).onLogoutSuccess(request, response, TEST_AUTH);
		verify(eventPublisher, times(1)).publishEvent(captor.capture());

		LogoutSuccessEvent event = captor.getValue();
		assertThat(event.getAuthentication()).isEqualTo(TEST_AUTH);
		assertThat(event.wasForcedLogout()).isFalse();
	}



	public static class TestLogoutHandler implements LogoutHandler {
		@Override
		public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

		}
	}
}
