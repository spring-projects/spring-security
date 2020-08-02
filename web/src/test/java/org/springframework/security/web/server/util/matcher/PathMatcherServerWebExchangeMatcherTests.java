/*
 * Copyright 2002-2017 the original author or authors.
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

package org.springframework.security.web.server.util.matcher;

import java.util.HashMap;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpResponse;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.session.DefaultWebSessionManager;
import org.springframework.web.util.pattern.PathPattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verifyZeroInteractions;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class PathMatcherServerWebExchangeMatcherTests {

	@Mock
	PathPattern pattern;

	@Mock
	PathPattern.PathMatchInfo pathMatchInfo;

	MockServerWebExchange exchange;

	PathPatternParserServerWebExchangeMatcher matcher;

	String path;

	@Before
	public void setup() {
		MockServerHttpRequest request = MockServerHttpRequest.post("/path").build();
		MockServerHttpResponse response = new MockServerHttpResponse();
		DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
		this.exchange = MockServerWebExchange.from(request);
		this.path = "/path";
		this.matcher = new PathPatternParserServerWebExchangeMatcher(this.pattern);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorPatternWhenPatternNullThenThrowsException() {
		new PathPatternParserServerWebExchangeMatcher((PathPattern) null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorPatternAndMethodWhenPatternNullThenThrowsException() {
		new PathPatternParserServerWebExchangeMatcher((PathPattern) null, HttpMethod.GET);
	}

	@Test
	public void matchesWhenPathMatcherTrueThenReturnTrue() {
		given(this.pattern.matches(any())).willReturn(true);
		given(this.pattern.matchAndExtract(any())).willReturn(this.pathMatchInfo);
		given(this.pathMatchInfo.getUriVariables()).willReturn(new HashMap<>());
		assertThat(this.matcher.matches(this.exchange).block().isMatch()).isTrue();
	}

	@Test
	public void matchesWhenPathMatcherFalseThenReturnFalse() {
		given(this.pattern.matches(any())).willReturn(false);
		assertThat(this.matcher.matches(this.exchange).block().isMatch()).isFalse();
	}

	@Test
	public void matchesWhenPathMatcherTrueAndMethodTrueThenReturnTrue() {
		this.matcher = new PathPatternParserServerWebExchangeMatcher(this.pattern,
				this.exchange.getRequest().getMethod());
		given(this.pattern.matches(any())).willReturn(true);
		given(this.pattern.matchAndExtract(any())).willReturn(this.pathMatchInfo);
		given(this.pathMatchInfo.getUriVariables()).willReturn(new HashMap<>());
		assertThat(this.matcher.matches(this.exchange).block().isMatch()).isTrue();
	}

	@Test
	public void matchesWhenPathMatcherTrueAndMethodFalseThenReturnFalse() {
		HttpMethod method = HttpMethod.OPTIONS;
		assertThat(this.exchange.getRequest().getMethod()).isNotEqualTo(method);
		this.matcher = new PathPatternParserServerWebExchangeMatcher(this.pattern, method);
		assertThat(this.matcher.matches(this.exchange).block().isMatch()).isFalse();
		verifyZeroInteractions(this.pattern);
	}

}
