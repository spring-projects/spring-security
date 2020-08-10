/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.web.concurrent;

import java.util.Date;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;

import org.junit.After;
import org.junit.Test;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.security.web.session.SimpleRedirectSessionInformationExpiredStrategy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

/**
 * Tests {@link ConcurrentSessionFilter}.
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @author Onur Kagan Ozcan
 */
public class ConcurrentSessionFilterTests {

	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorSessionRegistryWhenSessionRegistryNullThenExceptionThrown() {
		new ConcurrentSessionFilter(null);
	}

	@SuppressWarnings("deprecation")
	@Test(expected = IllegalArgumentException.class)
	public void constructorSessionRegistryExpiresUrlWhenInvalidUrlThenExceptionThrown() {
		new ConcurrentSessionFilter(new SessionRegistryImpl(), "oops");
	}

	@SuppressWarnings("deprecation")
	@Test(expected = IllegalArgumentException.class)
	public void constructorSessionRegistryExpiresUrlWhenSessionRegistryNullThenExceptionThrown() {
		new ConcurrentSessionFilter(null, "/expired");
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorSessionRegistrySessionInformationExpiredStrategyWhenStrategyIsNullThenThrowsException() {
		new ConcurrentSessionFilter(new SessionRegistryImpl(), (SessionInformationExpiredStrategy) null);
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

		// Setup our test fixture and registry to want this session to be expired

		SimpleRedirectSessionInformationExpiredStrategy expiredSessionStrategy = new SimpleRedirectSessionInformationExpiredStrategy(
				"/expired.jsp");
		ConcurrentSessionFilter filter = new ConcurrentSessionFilter(registry, expiredSessionStrategy);
		filter.setLogoutHandlers(new LogoutHandler[] { new SecurityContextLogoutHandler() });
		filter.afterPropertiesSet();

		FilterChain fc = mock(FilterChain.class);
		filter.doFilter(request, response, fc);
		// Expect that the filter chain will not be invoked, as we redirect to expiredUrl
		verifyZeroInteractions(fc);

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
		ConcurrentSessionFilter filter = new ConcurrentSessionFilter(registry);

		FilterChain fc = mock(FilterChain.class);
		filter.doFilter(request, response, fc);
		verifyZeroInteractions(fc);

		assertThat(response.getContentAsString())
				.isEqualTo("This session has been expired (possibly due to multiple concurrent logins being "
						+ "attempted as the same user).");
	}

	@Test(expected = IllegalArgumentException.class)
	public void detectsMissingSessionRegistry() {
		new ConcurrentSessionFilter(null);
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
		SimpleRedirectSessionInformationExpiredStrategy expiredSessionStrategy = new SimpleRedirectSessionInformationExpiredStrategy(
				"/expired.jsp");
		ConcurrentSessionFilter filter = new ConcurrentSessionFilter(registry, expiredSessionStrategy);

		Date lastRequest = registry.getSessionInformation(session.getId()).getLastRequest();

		Thread.sleep(1000);

		filter.doFilter(request, response, fc);

		verify(fc).doFilter(request, response);
		assertThat(registry.getSessionInformation(session.getId()).getLastRequest().after(lastRequest)).isTrue();
	}

	@Test
	public void doFilterWhenNoSessionThenChainIsContinued() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		RedirectStrategy redirect = mock(RedirectStrategy.class);
		SessionRegistry registry = mock(SessionRegistry.class);
		SessionInformation information = new SessionInformation("user", "sessionId",
				new Date(System.currentTimeMillis() - 1000));
		information.expireNow();
		when(registry.getSessionInformation(anyString())).thenReturn(information);

		String expiredUrl = "/expired";
		ConcurrentSessionFilter filter = new ConcurrentSessionFilter(registry, expiredUrl);
		filter.setRedirectStrategy(redirect);

		MockFilterChain chain = new MockFilterChain();

		filter.doFilter(request, response, chain);

		assertThat(chain.getRequest()).isNotNull();
	}

	@Test
	public void doFilterWhenNoSessionInformationThenChainIsContinued() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setSession(new MockHttpSession());
		MockHttpServletResponse response = new MockHttpServletResponse();

		RedirectStrategy redirect = mock(RedirectStrategy.class);
		SessionRegistry registry = mock(SessionRegistry.class);

		String expiredUrl = "/expired";
		ConcurrentSessionFilter filter = new ConcurrentSessionFilter(registry, expiredUrl);
		filter.setRedirectStrategy(redirect);

		MockFilterChain chain = new MockFilterChain();

		filter.doFilter(request, response, chain);

		assertThat(chain.getRequest()).isNotNull();
	}

	@Test
	public void doFilterWhenCustomRedirectStrategyThenCustomRedirectStrategyUsed() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpSession session = new MockHttpSession();
		request.setSession(session);
		MockHttpServletResponse response = new MockHttpServletResponse();

		RedirectStrategy redirect = mock(RedirectStrategy.class);
		SessionRegistry registry = mock(SessionRegistry.class);
		SessionInformation information = new SessionInformation("user", "sessionId",
				new Date(System.currentTimeMillis() - 1000));
		information.expireNow();
		when(registry.getSessionInformation(anyString())).thenReturn(information);

		String expiredUrl = "/expired";
		ConcurrentSessionFilter filter = new ConcurrentSessionFilter(registry, expiredUrl);
		filter.setRedirectStrategy(redirect);

		filter.doFilter(request, response, new MockFilterChain());

		verify(redirect).sendRedirect(request, response, expiredUrl);
	}

	@Test
	public void doFilterWhenOverrideThenCustomRedirectStrategyUsed() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpSession session = new MockHttpSession();
		request.setSession(session);
		MockHttpServletResponse response = new MockHttpServletResponse();

		RedirectStrategy redirect = mock(RedirectStrategy.class);
		SessionRegistry registry = mock(SessionRegistry.class);
		SessionInformation information = new SessionInformation("user", "sessionId",
				new Date(System.currentTimeMillis() - 1000));
		information.expireNow();
		when(registry.getSessionInformation(anyString())).thenReturn(information);

		final String expiredUrl = "/expired";
		ConcurrentSessionFilter filter = new ConcurrentSessionFilter(registry, expiredUrl + "will-be-overrridden") {
			/*
			 * (non-Javadoc)
			 *
			 * @see org.springframework.security.web.session.ConcurrentSessionFilter#
			 * determineExpiredUrl(javax.servlet.http.HttpServletRequest,
			 * org.springframework.security.core.session.SessionInformation)
			 */
			@Override
			protected String determineExpiredUrl(HttpServletRequest request, SessionInformation info) {
				return expiredUrl;
			}

		};
		filter.setRedirectStrategy(redirect);

		filter.doFilter(request, response, new MockFilterChain());

		verify(redirect).sendRedirect(request, response, expiredUrl);
	}

	@Test
	public void doFilterWhenNoExpiredUrlThenResponseWritten() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpSession session = new MockHttpSession();
		request.setSession(session);
		MockHttpServletResponse response = new MockHttpServletResponse();

		SessionRegistry registry = mock(SessionRegistry.class);
		SessionInformation information = new SessionInformation("user", "sessionId",
				new Date(System.currentTimeMillis() - 1000));
		information.expireNow();
		when(registry.getSessionInformation(anyString())).thenReturn(information);

		ConcurrentSessionFilter filter = new ConcurrentSessionFilter(registry);

		filter.doFilter(request, response, new MockFilterChain());

		assertThat(response.getContentAsString()).contains(
				"This session has been expired (possibly due to multiple concurrent logins being attempted as the same user).");
	}

	@Test
	public void doFilterWhenCustomLogoutHandlersThenHandlersUsed() throws Exception {
		LogoutHandler handler = mock(LogoutHandler.class);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpSession session = new MockHttpSession();
		request.setSession(session);
		MockHttpServletResponse response = new MockHttpServletResponse();

		SessionRegistry registry = mock(SessionRegistry.class);
		SessionInformation information = new SessionInformation("user", "sessionId",
				new Date(System.currentTimeMillis() - 1000));
		information.expireNow();
		when(registry.getSessionInformation(anyString())).thenReturn(information);

		ConcurrentSessionFilter filter = new ConcurrentSessionFilter(registry);
		filter.setLogoutHandlers(new LogoutHandler[] { handler });

		filter.doFilter(request, response, new MockFilterChain());

		verify(handler).logout(eq(request), eq(response), any());
	}

	@Test(expected = IllegalArgumentException.class)
	public void setLogoutHandlersWhenNullThenThrowsException() {
		ConcurrentSessionFilter filter = new ConcurrentSessionFilter(new SessionRegistryImpl());

		filter.setLogoutHandlers((List<LogoutHandler>) null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void setLogoutHandlersWhenEmptyThenThrowsException() {
		ConcurrentSessionFilter filter = new ConcurrentSessionFilter(new SessionRegistryImpl());

		filter.setLogoutHandlers(new LogoutHandler[0]);
	}

}
