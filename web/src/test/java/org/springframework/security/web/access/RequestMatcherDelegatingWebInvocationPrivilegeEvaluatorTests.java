/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.web.access;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests for {@link RequestMatcherDelegatingWebInvocationPrivilegeEvaluator}
 *
 * @author Marcus Da Coregio
 */
class RequestMatcherDelegatingWebInvocationPrivilegeEvaluatorTests {

	private final RequestMatcher alwaysMatch = mock(RequestMatcher.class);

	private final RequestMatcher alwaysDeny = mock(RequestMatcher.class);

	private final String uri = "/test";

	private final Authentication authentication = new TestingAuthenticationToken("user", "password", "ROLE_USER");

	@BeforeEach
	void setup() {
		given(this.alwaysMatch.matches(any())).willReturn(true);
		given(this.alwaysDeny.matches(any())).willReturn(false);
	}

	@Test
	void isAllowedWhenDelegatesEmptyThenAllowed() {
		RequestMatcherDelegatingWebInvocationPrivilegeEvaluator delegating = new RequestMatcherDelegatingWebInvocationPrivilegeEvaluator(
				Collections.emptyList());
		assertThat(delegating.isAllowed(this.uri, this.authentication)).isTrue();
	}

	@Test
	void isAllowedWhenNotMatchThenAllowed() {
		RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> notMatch = new RequestMatcherEntry<>(this.alwaysDeny,
				Collections.singletonList(TestWebInvocationPrivilegeEvaluator.alwaysAllow()));
		RequestMatcherDelegatingWebInvocationPrivilegeEvaluator delegating = new RequestMatcherDelegatingWebInvocationPrivilegeEvaluator(
				Collections.singletonList(notMatch));
		assertThat(delegating.isAllowed(this.uri, this.authentication)).isTrue();
		verify(notMatch.getRequestMatcher()).matches(any());
	}

	@Test
	void isAllowedWhenPrivilegeEvaluatorAllowThenAllowedTrue() {
		RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> delegate = new RequestMatcherEntry<>(
				this.alwaysMatch, Collections.singletonList(TestWebInvocationPrivilegeEvaluator.alwaysAllow()));
		RequestMatcherDelegatingWebInvocationPrivilegeEvaluator delegating = new RequestMatcherDelegatingWebInvocationPrivilegeEvaluator(
				Collections.singletonList(delegate));
		assertThat(delegating.isAllowed(this.uri, this.authentication)).isTrue();
	}

	@Test
	void isAllowedWhenPrivilegeEvaluatorDenyThenAllowedFalse() {
		RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> delegate = new RequestMatcherEntry<>(
				this.alwaysMatch, Collections.singletonList(TestWebInvocationPrivilegeEvaluator.alwaysDeny()));
		RequestMatcherDelegatingWebInvocationPrivilegeEvaluator delegating = new RequestMatcherDelegatingWebInvocationPrivilegeEvaluator(
				Collections.singletonList(delegate));
		assertThat(delegating.isAllowed(this.uri, this.authentication)).isFalse();
	}

	@Test
	void isAllowedWhenNotMatchThenMatchThenOnlySecondDelegateInvoked() {
		RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> notMatchDelegate = new RequestMatcherEntry<>(
				this.alwaysDeny, Collections.singletonList(TestWebInvocationPrivilegeEvaluator.alwaysAllow()));
		RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> matchDelegate = new RequestMatcherEntry<>(
				this.alwaysMatch, Collections.singletonList(TestWebInvocationPrivilegeEvaluator.alwaysAllow()));
		RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> spyNotMatchDelegate = spy(notMatchDelegate);
		RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> spyMatchDelegate = spy(matchDelegate);

		RequestMatcherDelegatingWebInvocationPrivilegeEvaluator delegating = new RequestMatcherDelegatingWebInvocationPrivilegeEvaluator(
				Arrays.asList(notMatchDelegate, spyMatchDelegate));
		assertThat(delegating.isAllowed(this.uri, this.authentication)).isTrue();
		verify(spyNotMatchDelegate.getRequestMatcher()).matches(any());
		verify(spyNotMatchDelegate, never()).getEntry();
		verify(spyMatchDelegate.getRequestMatcher()).matches(any());
		verify(spyMatchDelegate, times(2)).getEntry(); // 2 times, one for constructor and
														// other one in isAllowed
	}

	@Test
	void isAllowedWhenDelegatePrivilegeEvaluatorsEmptyThenAllowedTrue() {
		RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> delegate = new RequestMatcherEntry<>(
				this.alwaysMatch, Collections.emptyList());
		RequestMatcherDelegatingWebInvocationPrivilegeEvaluator delegating = new RequestMatcherDelegatingWebInvocationPrivilegeEvaluator(
				Collections.singletonList(delegate));
		assertThat(delegating.isAllowed(this.uri, this.authentication)).isTrue();
	}

	@Test
	void isAllowedWhenFirstDelegateDenyThenDoNotInvokeOthers() {
		WebInvocationPrivilegeEvaluator deny = TestWebInvocationPrivilegeEvaluator.alwaysDeny();
		WebInvocationPrivilegeEvaluator allow = TestWebInvocationPrivilegeEvaluator.alwaysAllow();
		WebInvocationPrivilegeEvaluator spyDeny = spy(deny);
		WebInvocationPrivilegeEvaluator spyAllow = spy(allow);
		RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> delegate = new RequestMatcherEntry<>(
				this.alwaysMatch, Arrays.asList(spyDeny, spyAllow));

		RequestMatcherDelegatingWebInvocationPrivilegeEvaluator delegating = new RequestMatcherDelegatingWebInvocationPrivilegeEvaluator(
				Collections.singletonList(delegate));

		assertThat(delegating.isAllowed(this.uri, this.authentication)).isFalse();
		verify(spyDeny).isAllowed(any(), any());
		verifyNoInteractions(spyAllow);
	}

	@Test
	void isAllowedWhenDifferentArgumentsThenCallSpecificIsAllowedInDelegate() {
		WebInvocationPrivilegeEvaluator deny = TestWebInvocationPrivilegeEvaluator.alwaysDeny();
		WebInvocationPrivilegeEvaluator spyDeny = spy(deny);
		RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> delegate = new RequestMatcherEntry<>(
				this.alwaysMatch, Collections.singletonList(spyDeny));

		RequestMatcherDelegatingWebInvocationPrivilegeEvaluator delegating = new RequestMatcherDelegatingWebInvocationPrivilegeEvaluator(
				Collections.singletonList(delegate));

		assertThat(delegating.isAllowed(this.uri, this.authentication)).isFalse();
		assertThat(delegating.isAllowed("/cp", this.uri, "GET", this.authentication)).isFalse();
		verify(spyDeny).isAllowed(any(), any());
		verify(spyDeny).isAllowed(any(), any(), any(), any());
		verifyNoMoreInteractions(spyDeny);
	}

	@Test
	void isAllowedWhenServletContextIsSetThenPassedFilterInvocationHttpServletRequestHasServletContext() {
		Authentication token = new TestingAuthenticationToken("test", "Password", "MOCK_INDEX");
		MockServletContext servletContext = new MockServletContext();
		ArgumentCaptor<HttpServletRequest> argumentCaptor = ArgumentCaptor.forClass(HttpServletRequest.class);
		RequestMatcher requestMatcher = mock(RequestMatcher.class);
		WebInvocationPrivilegeEvaluator wipe = mock(WebInvocationPrivilegeEvaluator.class);
		RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> delegate = new RequestMatcherEntry<>(requestMatcher,
				Collections.singletonList(wipe));
		RequestMatcherDelegatingWebInvocationPrivilegeEvaluator requestMatcherWipe = new RequestMatcherDelegatingWebInvocationPrivilegeEvaluator(
				Collections.singletonList(delegate));
		requestMatcherWipe.setServletContext(servletContext);
		requestMatcherWipe.isAllowed("/foo/index.jsp", token);
		verify(requestMatcher).matches(argumentCaptor.capture());
		assertThat(argumentCaptor.getValue().getServletContext()).isNotNull();
	}

	@Test
	void constructorWhenPrivilegeEvaluatorsNullThenException() {
		RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> entry = new RequestMatcherEntry<>(this.alwaysMatch,
				null);
		assertThatIllegalArgumentException().isThrownBy(
				() -> new RequestMatcherDelegatingWebInvocationPrivilegeEvaluator(Collections.singletonList(entry)))
				.withMessageContaining("webInvocationPrivilegeEvaluators cannot be null");
	}

	@Test
	void constructorWhenRequestMatcherNullThenException() {
		RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> entry = new RequestMatcherEntry<>(null,
				Collections.singletonList(mock(WebInvocationPrivilegeEvaluator.class)));
		assertThatIllegalArgumentException().isThrownBy(
				() -> new RequestMatcherDelegatingWebInvocationPrivilegeEvaluator(Collections.singletonList(entry)))
				.withMessageContaining("requestMatcher cannot be null");
	}

}
