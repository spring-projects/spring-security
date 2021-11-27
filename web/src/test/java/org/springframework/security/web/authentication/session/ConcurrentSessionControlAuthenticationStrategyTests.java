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

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.BDDMockito.given;

/**
 * @author Rob Winch
 *
 */
@ExtendWith(MockitoExtension.class)
public class ConcurrentSessionControlAuthenticationStrategyTests {

	@Mock
	private SessionRegistry sessionRegistry;

	private Authentication authentication;

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private SessionInformation sessionInformation;

	private ConcurrentSessionControlAuthenticationStrategy strategy;

	@BeforeEach
	public void setup() {
		this.authentication = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.sessionInformation = new SessionInformation(this.authentication.getPrincipal(), "unique",
				new Date(1374766134216L));
		this.strategy = new ConcurrentSessionControlAuthenticationStrategy(this.sessionRegistry);
	}

	@Test
	public void constructorNullRegistry() {
		assertThatIllegalArgumentException().isThrownBy(() -> new ConcurrentSessionControlAuthenticationStrategy(null));
	}

	@Test
	public void noRegisteredSession() {
		given(this.sessionRegistry.getAllSessions(any(), anyBoolean()))
				.willReturn(Collections.<SessionInformation>emptyList());
		this.strategy.setMaximumSessions(1);
		this.strategy.setExceptionIfMaximumExceeded(true);
		this.strategy.onAuthentication(this.authentication, this.request, this.response);
		// no exception
	}

	@Test
	public void maxSessionsSameSessionId() {
		MockHttpSession session = new MockHttpSession(new MockServletContext(), this.sessionInformation.getSessionId());
		this.request.setSession(session);
		given(this.sessionRegistry.getAllSessions(any(), anyBoolean()))
				.willReturn(Collections.<SessionInformation>singletonList(this.sessionInformation));
		this.strategy.setMaximumSessions(1);
		this.strategy.setExceptionIfMaximumExceeded(true);
		this.strategy.onAuthentication(this.authentication, this.request, this.response);
		// no exception
	}

	@Test
	public void maxSessionsWithException() {
		given(this.sessionRegistry.getAllSessions(any(), anyBoolean()))
				.willReturn(Collections.<SessionInformation>singletonList(this.sessionInformation));
		this.strategy.setMaximumSessions(1);
		this.strategy.setExceptionIfMaximumExceeded(true);
		assertThatExceptionOfType(SessionAuthenticationException.class)
				.isThrownBy(() -> this.strategy.onAuthentication(this.authentication, this.request, this.response));
	}

	@Test
	public void maxSessionsExpireExistingUser() {
		given(this.sessionRegistry.getAllSessions(any(), anyBoolean()))
				.willReturn(Collections.<SessionInformation>singletonList(this.sessionInformation));
		this.strategy.setMaximumSessions(1);
		this.strategy.onAuthentication(this.authentication, this.request, this.response);
		assertThat(this.sessionInformation.isExpired()).isTrue();
	}

	@Test
	public void maxSessionsExpireLeastRecentExistingUser() {
		SessionInformation moreRecentSessionInfo = new SessionInformation(this.authentication.getPrincipal(), "unique",
				new Date(1374766999999L));
		given(this.sessionRegistry.getAllSessions(any(), anyBoolean()))
				.willReturn(Arrays.<SessionInformation>asList(moreRecentSessionInfo, this.sessionInformation));
		this.strategy.setMaximumSessions(2);
		this.strategy.onAuthentication(this.authentication, this.request, this.response);
		assertThat(this.sessionInformation.isExpired()).isTrue();
	}

	@Test
	public void onAuthenticationWhenMaxSessionsExceededByTwoThenTwoSessionsExpired() {
		SessionInformation oldestSessionInfo = new SessionInformation(this.authentication.getPrincipal(), "unique1",
				new Date(1374766134214L));
		SessionInformation secondOldestSessionInfo = new SessionInformation(this.authentication.getPrincipal(),
				"unique2", new Date(1374766134215L));
		given(this.sessionRegistry.getAllSessions(any(), anyBoolean())).willReturn(
				Arrays.<SessionInformation>asList(oldestSessionInfo, secondOldestSessionInfo, this.sessionInformation));
		this.strategy.setMaximumSessions(2);
		this.strategy.onAuthentication(this.authentication, this.request, this.response);
		assertThat(oldestSessionInfo.isExpired()).isTrue();
		assertThat(secondOldestSessionInfo.isExpired()).isTrue();
		assertThat(this.sessionInformation.isExpired()).isFalse();
	}

	@Test
	public void setMessageSourceNull() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.strategy.setMessageSource(null));
	}

}
