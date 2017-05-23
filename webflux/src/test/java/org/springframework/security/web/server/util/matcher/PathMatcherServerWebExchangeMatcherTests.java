/*
 *
 *  * Copyright 2002-2017 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */
package org.springframework.security.web.server.util.matcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpResponse;
import org.springframework.mock.http.server.reactive.MockServerWebExchange;
import org.springframework.util.PathMatcher;
import org.springframework.web.server.adapter.DefaultServerWebExchange;
import org.springframework.web.server.session.DefaultWebSessionManager;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class PathMatcherServerWebExchangeMatcherTests {
	@Mock
	PathMatcher pathMatcher;
	MockServerWebExchange exchange;
	PathMatcherServerWebExchangeMatcher matcher;
	String pattern;
	String path;

	@Before
	public void setup() {
		MockServerHttpRequest request = MockServerHttpRequest.post("/path").build();
		MockServerHttpResponse response = new MockServerHttpResponse();
		DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
		exchange = request.toExchange();
		pattern = "/pattern";
		path = "/path";

		matcher = new PathMatcherServerWebExchangeMatcher(pattern);
		matcher.setPathMatcher(pathMatcher);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorPatternWhenPatternNullThenThrowsException() {
		new PathMatcherServerWebExchangeMatcher(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorPatternAndMethodWhenPatternNullThenThrowsException() {
		new PathMatcherServerWebExchangeMatcher(null, HttpMethod.GET);
	}

	@Test
	public void matchesWhenPathMatcherTrueThenReturnTrue() {
		when(pathMatcher.match(pattern, path)).thenReturn(true);

		assertThat(matcher.matches(exchange).block().isMatch()).isTrue();
	}

	@Test
	public void matchesWhenPathMatcherFalseThenReturnFalse() {
		when(pathMatcher.match(pattern, path)).thenReturn(false);

		assertThat(matcher.matches(exchange).block().isMatch()).isFalse();

		verify(pathMatcher).match(pattern, path);
	}

	@Test
	public void matchesWhenPathMatcherTrueAndMethodTrueThenReturnTrue() {
		matcher = new PathMatcherServerWebExchangeMatcher(pattern, exchange.getRequest().getMethod());
		matcher.setPathMatcher(pathMatcher);
		when(pathMatcher.match(pattern, path)).thenReturn(true);

		assertThat(matcher.matches(exchange).block().isMatch()).isTrue();
	}

	@Test
	public void matchesWhenPathMatcherTrueAndMethodFalseThenReturnFalse() {
		HttpMethod method = HttpMethod.OPTIONS;
		assertThat(exchange.getRequest().getMethod()).isNotEqualTo(method);
		matcher = new PathMatcherServerWebExchangeMatcher(pattern, method);
		matcher.setPathMatcher(pathMatcher);

		assertThat(matcher.matches(exchange).block().isMatch()).isFalse();

		verifyZeroInteractions(pathMatcher);
	}

	@Test(expected = IllegalArgumentException.class)
	public void setPathMatcherWhenNullThenThrowException() {
		matcher.setPathMatcher(null);
	}
}
