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

import java.util.Collections;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class AndServerWebExchangeMatcherTests {

	@Mock
	ServerWebExchange exchange;

	@Mock
	ServerWebExchangeMatcher matcher1;

	@Mock
	ServerWebExchangeMatcher matcher2;

	AndServerWebExchangeMatcher matcher;

	@Before
	public void setUp() {
		this.matcher = new AndServerWebExchangeMatcher(this.matcher1, this.matcher2);
	}

	@Test
	public void matchesWhenTrueTrueThenTrue() {
		Map<String, Object> params1 = Collections.singletonMap("foo", "bar");
		Map<String, Object> params2 = Collections.singletonMap("x", "y");
		given(this.matcher1.matches(this.exchange)).willReturn(ServerWebExchangeMatcher.MatchResult.match(params1));
		given(this.matcher2.matches(this.exchange)).willReturn(ServerWebExchangeMatcher.MatchResult.match(params2));
		ServerWebExchangeMatcher.MatchResult matches = this.matcher.matches(this.exchange).block();
		assertThat(matches.isMatch()).isTrue();
		assertThat(matches.getVariables()).hasSize(2);
		assertThat(matches.getVariables()).containsAllEntriesOf(params1);
		assertThat(matches.getVariables()).containsAllEntriesOf(params2);
		verify(this.matcher1).matches(this.exchange);
		verify(this.matcher2).matches(this.exchange);
	}

	@Test
	public void matchesWhenFalseFalseThenFalseAndMatcher2NotInvoked() {
		given(this.matcher1.matches(this.exchange)).willReturn(ServerWebExchangeMatcher.MatchResult.notMatch());
		ServerWebExchangeMatcher.MatchResult matches = this.matcher.matches(this.exchange).block();
		assertThat(matches.isMatch()).isFalse();
		assertThat(matches.getVariables()).isEmpty();
		verify(this.matcher1).matches(this.exchange);
		verify(this.matcher2, never()).matches(this.exchange);
	}

	@Test
	public void matchesWhenTrueFalseThenFalse() {
		Map<String, Object> params = Collections.singletonMap("foo", "bar");
		given(this.matcher1.matches(this.exchange)).willReturn(ServerWebExchangeMatcher.MatchResult.match(params));
		given(this.matcher2.matches(this.exchange)).willReturn(ServerWebExchangeMatcher.MatchResult.notMatch());
		ServerWebExchangeMatcher.MatchResult matches = this.matcher.matches(this.exchange).block();
		assertThat(matches.isMatch()).isFalse();
		assertThat(matches.getVariables()).isEmpty();
		verify(this.matcher1).matches(this.exchange);
		verify(this.matcher2).matches(this.exchange);
	}

	@Test
	public void matchesWhenFalseTrueThenFalse() {
		given(this.matcher1.matches(this.exchange)).willReturn(ServerWebExchangeMatcher.MatchResult.notMatch());
		ServerWebExchangeMatcher.MatchResult matches = this.matcher.matches(this.exchange).block();
		assertThat(matches.isMatch()).isFalse();
		assertThat(matches.getVariables()).isEmpty();
		verify(this.matcher1).matches(this.exchange);
		verify(this.matcher2, never()).matches(this.exchange);
	}

}
