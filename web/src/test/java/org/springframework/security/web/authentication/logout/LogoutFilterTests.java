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

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.event.LogoutSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.ServletException;
import java.io.IOException;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Test cases for {@link LogoutFilter}.
 *
 * @author Kazuki Shimizu
 * @since 4.1.1
 */
@RunWith(PowerMockRunner.class)
public class LogoutFilterTests {

	private final LogoutFilter filter = new LogoutFilter("/logoutSuccess", new SecurityContextLogoutHandler());
	private final MockHttpSession session = new MockHttpSession();
	private final MockHttpServletRequest request = new MockHttpServletRequest();
	private final MockHttpServletResponse response = new MockHttpServletResponse();
	private final MockFilterChain filterChain = new MockFilterChain();

	@Mock
	private ApplicationEventPublisher applicationEventPublisher;

	@Mock
	private Authentication authentication;

	@Before
	public void setUp() {
		filter.setApplicationEventPublisher(applicationEventPublisher);
		request.setSession(session);
	}

	@Before
	public void setUpSecurityContext() {
		SecurityContextHolder.getContext().setAuthentication(authentication);
	}

	@AfterClass
	public static void cleanupSecurityContextHolder() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void testLogoutPath() throws IOException, ServletException {
		// setUp
		request.setRequestURI("/context/logout");
		request.setServletPath("/logout");

		ArgumentCaptor<LogoutSuccessEvent> eventCaptor = ArgumentCaptor.forClass(LogoutSuccessEvent.class);
		doNothing().when(applicationEventPublisher).publishEvent(eventCaptor.capture());

		// test
		filter.doFilter(request, response, filterChain);

		// assert
		assertThat(session.isInvalid()).isTrue();
		assertThat(response.getRedirectedUrl()).isEqualTo("/logoutSuccess");
		assertThat(filterChain.getRequest()).isNull();
		assertThat(filterChain.getResponse()).isNull();
		LogoutSuccessEvent actualLogoutSuccessEvent = eventCaptor.getValue();
		assertThat(actualLogoutSuccessEvent.isExpired()).isFalse();
	}

	@Test
	public void testLogoutPathWhenAuthenticationIsNull() throws IOException, ServletException {
		// setUp
		request.setRequestURI("/context/logout");
		request.setServletPath("/logout");

		SecurityContextHolder.getContext().setAuthentication(null);

		// test
		filter.doFilter(request, response, filterChain);

		// assert
		assertThat(session.isInvalid()).isTrue();
		assertThat(response.getRedirectedUrl()).isEqualTo("/logoutSuccess");
		assertThat(filterChain.getRequest()).isNull();
		assertThat(filterChain.getResponse()).isNull();
		verify(applicationEventPublisher, never()).publishEvent(anyObject());
	}

	@Test
	public void testLogoutPathWithoutApplicationEventPublisher() throws IOException, ServletException {
		// setUp
		request.setRequestURI("/context/logout");
		request.setServletPath("/logout");

		filter.setApplicationEventPublisher(null);

		// test
		filter.doFilter(request, response, filterChain);

		// assert
		assertThat(session.isInvalid()).isTrue();
		assertThat(response.getRedirectedUrl()).isEqualTo("/logoutSuccess");
		assertThat(filterChain.getRequest()).isNull();
		assertThat(filterChain.getResponse()).isNull();
		verify(applicationEventPublisher, never()).publishEvent(anyObject());
	}

	@Test
	public void testOtherPath() throws IOException, ServletException {
		// setUp
		request.setRequestURI("/context/accounts");
		request.setServletPath("/accounts");

		// test
		filter.doFilter(request, response, filterChain);

		// assert
		assertThat(session.isInvalid()).isFalse();
		assertThat(response.getRedirectedUrl()).isNull();
		assertThat(filterChain.getRequest()).isSameAs(request);
		assertThat(filterChain.getResponse()).isSameAs(response);

		verify(applicationEventPublisher, never()).publishEvent(anyObject());
	}

}
