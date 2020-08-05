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

package org.springframework.security.web.authentication.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;

/**
 * @author Rob Winch
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class ConcurrentSessionControlAuthenticationStrategyTests {

	@Mock
	private SessionRegistry sessionRegistry;

	private Authentication authentication;

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private SessionInformation sessionInformation;

	private ConcurrentSessionControlAuthenticationStrategy strategy;

	@Before
	public void setup() {
		authentication = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		request = new MockHttpServletRequest();
		response = new MockHttpServletResponse();
		sessionInformation = new SessionInformation(authentication.getPrincipal(), "unique", new Date(1374766134216L));

		strategy = new ConcurrentSessionControlAuthenticationStrategy(sessionRegistry);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullRegistry() {
		new ConcurrentSessionControlAuthenticationStrategy(null);
	}

	@Test
	public void noRegisteredSession() {
		when(sessionRegistry.getAllSessions(any(), anyBoolean()))
				.thenReturn(Collections.<SessionInformation>emptyList());
		strategy.setMaximumSessions(1);
		strategy.setExceptionIfMaximumExceeded(true);

		strategy.onAuthentication(authentication, request, response);

		// no exception
	}

	@Test
	public void maxSessionsSameSessionId() {
		MockHttpSession session = new MockHttpSession(new MockServletContext(), sessionInformation.getSessionId());
		request.setSession(session);
		when(sessionRegistry.getAllSessions(any(), anyBoolean()))
				.thenReturn(Collections.<SessionInformation>singletonList(sessionInformation));
		strategy.setMaximumSessions(1);
		strategy.setExceptionIfMaximumExceeded(true);

		strategy.onAuthentication(authentication, request, response);

		// no exception
	}

	@Test(expected = SessionAuthenticationException.class)
	public void maxSessionsWithException() {
		when(sessionRegistry.getAllSessions(any(), anyBoolean()))
				.thenReturn(Collections.<SessionInformation>singletonList(sessionInformation));
		strategy.setMaximumSessions(1);
		strategy.setExceptionIfMaximumExceeded(true);

		strategy.onAuthentication(authentication, request, response);
	}

	@Test
	public void maxSessionsExpireExistingUser() {
		when(sessionRegistry.getAllSessions(any(), anyBoolean()))
				.thenReturn(Collections.<SessionInformation>singletonList(sessionInformation));
		strategy.setMaximumSessions(1);

		strategy.onAuthentication(authentication, request, response);

		assertThat(sessionInformation.isExpired()).isTrue();
	}

	@Test
	public void maxSessionsExpireLeastRecentExistingUser() {
		SessionInformation moreRecentSessionInfo = new SessionInformation(authentication.getPrincipal(), "unique",
				new Date(1374766999999L));
		when(sessionRegistry.getAllSessions(any(), anyBoolean()))
				.thenReturn(Arrays.<SessionInformation>asList(moreRecentSessionInfo, sessionInformation));
		strategy.setMaximumSessions(2);

		strategy.onAuthentication(authentication, request, response);

		assertThat(sessionInformation.isExpired()).isTrue();
	}

	@Test
	public void onAuthenticationWhenMaxSessionsExceededByTwoThenTwoSessionsExpired() {
		SessionInformation oldestSessionInfo = new SessionInformation(authentication.getPrincipal(), "unique1",
				new Date(1374766134214L));
		SessionInformation secondOldestSessionInfo = new SessionInformation(authentication.getPrincipal(), "unique2",
				new Date(1374766134215L));
		when(sessionRegistry.getAllSessions(any(), anyBoolean())).thenReturn(
				Arrays.<SessionInformation>asList(oldestSessionInfo, secondOldestSessionInfo, sessionInformation));
		strategy.setMaximumSessions(2);

		strategy.onAuthentication(authentication, request, response);

		assertThat(oldestSessionInfo.isExpired()).isTrue();
		assertThat(secondOldestSessionInfo.isExpired()).isTrue();
		assertThat(sessionInformation.isExpired()).isFalse();
	}

	@Test(expected = IllegalArgumentException.class)
	public void setMessageSourceNull() {
		strategy.setMessageSource(null);
	}

}
