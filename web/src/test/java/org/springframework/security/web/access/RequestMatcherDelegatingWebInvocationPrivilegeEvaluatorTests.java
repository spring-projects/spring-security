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

package org.springframework.security.web.access;

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
		WebInvocationPrivilegeEvaluator delegating = evaluator();
		assertThat(delegating.isAllowed(this.uri, this.authentication)).isTrue();
	}

	@Test
	void isAllowedWhenNotMatchThenAllowed() {
		RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> notMatch = entry(this.alwaysDeny,
				TestWebInvocationPrivilegeEvaluators.alwaysAllow());
		WebInvocationPrivilegeEvaluator delegating = evaluator(notMatch);
		assertThat(delegating.isAllowed(this.uri, this.authentication)).isTrue();
		verify(notMatch.getRequestMatcher()).matches(any());
	}

	@Test
	void isAllowedWhenPrivilegeEvaluatorAllowThenAllowedTrue() {
		WebInvocationPrivilegeEvaluator delegating = evaluator(allow(this.alwaysMatch));
		assertThat(delegating.isAllowed(this.uri, this.authentication)).isTrue();
	}

	@Test
	void isAllowedWhenPrivilegeEvaluatorDenyThenAllowedFalse() {
		WebInvocationPrivilegeEvaluator delegating = evaluator(deny(this.alwaysMatch));
		assertThat(delegating.isAllowed(this.uri, this.authentication)).isFalse();
	}

	@Test
	void isAllowedWhenNotMatchThenMatchThenOnlySecondDelegateInvoked() {
		RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> notMatchDelegate = entry(this.alwaysDeny,
				TestWebInvocationPrivilegeEvaluators.alwaysAllow());
		RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> matchDelegate = entry(this.alwaysMatch,
				TestWebInvocationPrivilegeEvaluators.alwaysAllow());
		RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> spyNotMatchDelegate = spy(notMatchDelegate);
		RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> spyMatchDelegate = spy(matchDelegate);

		WebInvocationPrivilegeEvaluator delegating = evaluator(notMatchDelegate, spyMatchDelegate);
		assertThat(delegating.isAllowed(this.uri, this.authentication)).isTrue();
		verify(spyNotMatchDelegate.getRequestMatcher()).matches(any());
		verify(spyNotMatchDelegate, never()).getEntry();
		verify(spyMatchDelegate.getRequestMatcher()).matches(any());
		verify(spyMatchDelegate, times(2)).getEntry(); // 2 times, one for constructor and
														// other one in isAllowed
	}

	@Test
	void isAllowedWhenDelegatePrivilegeEvaluatorsEmptyThenAllowedTrue() {
		RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> delegate = entry(this.alwaysMatch);
		WebInvocationPrivilegeEvaluator delegating = evaluator(delegate);
		assertThat(delegating.isAllowed(this.uri, this.authentication)).isTrue();
	}

	@Test
	void isAllowedWhenFirstDelegateDenyThenDoNotInvokeOthers() {
		WebInvocationPrivilegeEvaluator deny = TestWebInvocationPrivilegeEvaluators.alwaysDeny();
		WebInvocationPrivilegeEvaluator allow = TestWebInvocationPrivilegeEvaluators.alwaysAllow();
		WebInvocationPrivilegeEvaluator spyDeny = spy(deny);
		WebInvocationPrivilegeEvaluator spyAllow = spy(allow);
		RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> delegate = entry(this.alwaysMatch, spyDeny,
				spyAllow);

		WebInvocationPrivilegeEvaluator delegating = evaluator(delegate);

		assertThat(delegating.isAllowed(this.uri, this.authentication)).isFalse();
		verify(spyDeny).isAllowed(any(), any());
		verifyNoInteractions(spyAllow);
	}

	@Test
	void isAllowedWhenDifferentArgumentsThenCallSpecificIsAllowedInDelegate() {
		WebInvocationPrivilegeEvaluator deny = TestWebInvocationPrivilegeEvaluators.alwaysDeny();
		WebInvocationPrivilegeEvaluator spyDeny = spy(deny);
		RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> delegate = entry(this.alwaysMatch, spyDeny);

		WebInvocationPrivilegeEvaluator delegating = evaluator(delegate);

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
		RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> delegate = entry(requestMatcher, wipe);
		RequestMatcherDelegatingWebInvocationPrivilegeEvaluator requestMatcherWipe = evaluator(delegate);
		requestMatcherWipe.setServletContext(servletContext);
		requestMatcherWipe.isAllowed("/foo/index.jsp", token);
		verify(requestMatcher).matches(argumentCaptor.capture());
		assertThat(argumentCaptor.getValue().getServletContext()).isNotNull();
	}

	@Test
	void constructorWhenPrivilegeEvaluatorsNullThenException() {
		RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> entry = new RequestMatcherEntry<>(this.alwaysMatch,
				null);
		assertThatIllegalArgumentException().isThrownBy(() -> evaluator(entry))
			.withMessageContaining("webInvocationPrivilegeEvaluators cannot be null");
	}

	@Test
	void constructorWhenRequestMatcherNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> evaluator(deny(null)))
			.withMessageContaining("requestMatcher cannot be null");
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private RequestMatcherDelegatingWebInvocationPrivilegeEvaluator evaluator(RequestMatcherEntry... entries) {
		return new RequestMatcherDelegatingWebInvocationPrivilegeEvaluator(List.of(entries));
	}

	private RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> allow(RequestMatcher requestMatcher) {
		return entry(requestMatcher, TestWebInvocationPrivilegeEvaluators.alwaysAllow());
	}

	private RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> deny(RequestMatcher requestMatcher) {
		return entry(requestMatcher, TestWebInvocationPrivilegeEvaluators.alwaysDeny());
	}

	private RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> entry(RequestMatcher requestMatcher,
			WebInvocationPrivilegeEvaluator... evaluators) {
		return new RequestMatcherEntry<>(requestMatcher, List.of(evaluators));
	}

}
