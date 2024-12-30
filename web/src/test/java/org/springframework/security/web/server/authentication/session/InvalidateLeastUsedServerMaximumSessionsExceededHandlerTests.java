/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.server.authentication.session;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.mock.web.server.MockWebSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.ReactiveSessionInformation;
import org.springframework.security.web.server.authentication.InvalidateLeastUsedServerMaximumSessionsExceededHandler;
import org.springframework.security.web.server.authentication.MaximumSessionsContext;
import org.springframework.web.server.session.InMemoryWebSessionStore;
import org.springframework.web.server.session.WebSessionStore;

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests for {@link InvalidateLeastUsedServerMaximumSessionsExceededHandler}
 *
 * @author Marcus da Coregio
 */
class InvalidateLeastUsedServerMaximumSessionsExceededHandlerTests {

	InvalidateLeastUsedServerMaximumSessionsExceededHandler handler;

	WebSessionStore webSessionStore = spy(new InMemoryWebSessionStore());

	@BeforeEach
	void setup() {
		this.handler = new InvalidateLeastUsedServerMaximumSessionsExceededHandler(this.webSessionStore);
	}

	@Test
	void handleWhenInvokedThenInvalidatesLeastRecentlyUsedSessions() {
		ReactiveSessionInformation session1 = mock(ReactiveSessionInformation.class);
		ReactiveSessionInformation session2 = mock(ReactiveSessionInformation.class);
		given(session1.getLastAccessTime()).willReturn(Instant.ofEpochMilli(1700827760010L));
		given(session2.getLastAccessTime()).willReturn(Instant.ofEpochMilli(1700827760000L));
		given(session1.getSessionId()).willReturn("session1");
		given(session2.getSessionId()).willReturn("session2");
		given(session2.invalidate()).willReturn(Mono.empty());

		MaximumSessionsContext context = new MaximumSessionsContext(mock(Authentication.class),
				List.of(session1, session2), 2, createWebSession());

		this.handler.handle(context).block();

		verify(session2).invalidate();
		verify(session1).getLastAccessTime(); // used by comparator to sort the sessions
		verify(session2).getLastAccessTime(); // used by comparator to sort the sessions
		verify(session1).getSessionId();
		verify(session2, times(2)).getSessionId(); // used to invalidate session against
													// the
		// WebSessionStore
		verify(this.webSessionStore).removeSession("session2");
		verifyNoMoreInteractions(this.webSessionStore);
		verifyNoMoreInteractions(session2);
		verifyNoMoreInteractions(session1);
	}

	@Test
	void handleWhenMoreThanOneSessionToInvalidateThenInvalidatesAllOfThem() {
		ReactiveSessionInformation session1 = mock(ReactiveSessionInformation.class);
		ReactiveSessionInformation session2 = mock(ReactiveSessionInformation.class);
		ReactiveSessionInformation session3 = mock(ReactiveSessionInformation.class);
		given(session1.getLastAccessTime()).willReturn(Instant.ofEpochMilli(1700827760010L));
		given(session2.getLastAccessTime()).willReturn(Instant.ofEpochMilli(1700827760020L));
		given(session3.getLastAccessTime()).willReturn(Instant.ofEpochMilli(1700827760030L));
		given(session1.invalidate()).willReturn(Mono.empty());
		given(session2.invalidate()).willReturn(Mono.empty());
		given(session1.getSessionId()).willReturn("session1");
		given(session2.getSessionId()).willReturn("session2");
		given(session3.getSessionId()).willReturn("session3");

		MaximumSessionsContext context = new MaximumSessionsContext(mock(Authentication.class),
				List.of(session1, session2, session3), 2, createWebSession());
		this.handler.handle(context).block();

		// @formatter:off
		verify(session1).invalidate();
		verify(session2).invalidate();
		verify(session1, times(2)).getSessionId();
		verify(session2, times(2)).getSessionId();
		verify(session3).getSessionId();
		verify(session1, atLeastOnce()).getLastAccessTime(); // used by comparator to sort the sessions
		verify(session2, atLeastOnce()).getLastAccessTime(); // used by comparator to sort the sessions
		verify(session3, atLeastOnce()).getLastAccessTime(); // used by comparator to sort the sessions
		verify(this.webSessionStore).removeSession("session1");
		verify(this.webSessionStore).removeSession("session2");
		verifyNoMoreInteractions(this.webSessionStore);
		verifyNoMoreInteractions(session1);
		verifyNoMoreInteractions(session2);
		verifyNoMoreInteractions(session3);
		// @formatter:on
	}

	@Test
	void handleWhenCurrentSessionIsRegisteredThenDoNotInvalidateCurrentSession() {
		ReactiveSessionInformation session1 = mock(ReactiveSessionInformation.class);
		ReactiveSessionInformation session2 = mock(ReactiveSessionInformation.class);
		MockWebSession currentSession = createWebSession();
		given(session1.getLastAccessTime()).willReturn(Instant.ofEpochMilli(1700827760010L));
		given(session2.getLastAccessTime()).willReturn(Instant.ofEpochMilli(1700827760000L));
		given(session1.getSessionId()).willReturn("session1");
		given(session2.getSessionId()).willReturn(currentSession.getId());
		given(session1.invalidate()).willReturn(Mono.empty());

		MaximumSessionsContext context = new MaximumSessionsContext(mock(Authentication.class),
				List.of(session1, session2), 1, currentSession);

		this.handler.handle(context).block();

		verify(session1).invalidate();
		verify(session2).getSessionId();
		verify(session1, times(2)).getSessionId();
		verify(this.webSessionStore).removeSession("session1");
		verifyNoMoreInteractions(this.webSessionStore);
		verifyNoMoreInteractions(session2);
		verifyNoMoreInteractions(session1);
	}

	private MockWebSession createWebSession() {
		return new MockWebSession();
	}

}
