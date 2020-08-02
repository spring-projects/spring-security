/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.web.server.authorization;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import reactor.core.publisher.Mono;

import org.springframework.security.web.server.authorization.ServerWebExchangeDelegatingServerAccessDeniedHandler.DelegateEntry;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher.MatchResult;
import org.springframework.web.server.ServerWebExchange;

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

public class ServerWebExchangeDelegatingServerAccessDeniedHandlerTests {

	private ServerWebExchangeDelegatingServerAccessDeniedHandler delegator;

	private List<ServerWebExchangeDelegatingServerAccessDeniedHandler.DelegateEntry> entries;

	private ServerAccessDeniedHandler accessDeniedHandler;

	private ServerWebExchange exchange;

	@Before
	public void setup() {
		this.accessDeniedHandler = mock(ServerAccessDeniedHandler.class);
		this.entries = new ArrayList<>();
		this.exchange = mock(ServerWebExchange.class);
	}

	@Test
	public void handleWhenNothingMatchesThenOnlyDefaultHandlerInvoked() {
		ServerAccessDeniedHandler handler = mock(ServerAccessDeniedHandler.class);
		ServerWebExchangeMatcher matcher = mock(ServerWebExchangeMatcher.class);
		given(matcher.matches(this.exchange)).willReturn(MatchResult.notMatch());
		given(handler.handle(this.exchange, null)).willReturn(Mono.empty());
		given(this.accessDeniedHandler.handle(this.exchange, null)).willReturn(Mono.empty());
		this.entries.add(new DelegateEntry(matcher, handler));
		this.delegator = new ServerWebExchangeDelegatingServerAccessDeniedHandler(this.entries);
		this.delegator.setDefaultAccessDeniedHandler(this.accessDeniedHandler);
		this.delegator.handle(this.exchange, null).block();
		verify(this.accessDeniedHandler).handle(this.exchange, null);
		verify(handler, never()).handle(this.exchange, null);
	}

	@Test
	public void handleWhenFirstMatchesThenOnlyFirstInvoked() {
		ServerAccessDeniedHandler firstHandler = mock(ServerAccessDeniedHandler.class);
		ServerWebExchangeMatcher firstMatcher = mock(ServerWebExchangeMatcher.class);
		ServerAccessDeniedHandler secondHandler = mock(ServerAccessDeniedHandler.class);
		ServerWebExchangeMatcher secondMatcher = mock(ServerWebExchangeMatcher.class);
		given(firstMatcher.matches(this.exchange)).willReturn(MatchResult.match());
		given(firstHandler.handle(this.exchange, null)).willReturn(Mono.empty());
		given(secondHandler.handle(this.exchange, null)).willReturn(Mono.empty());
		this.entries.add(new DelegateEntry(firstMatcher, firstHandler));
		this.entries.add(new DelegateEntry(secondMatcher, secondHandler));
		this.delegator = new ServerWebExchangeDelegatingServerAccessDeniedHandler(this.entries);
		this.delegator.setDefaultAccessDeniedHandler(this.accessDeniedHandler);
		this.delegator.handle(this.exchange, null).block();
		verify(firstHandler).handle(this.exchange, null);
		verify(secondHandler, never()).handle(this.exchange, null);
		verify(this.accessDeniedHandler, never()).handle(this.exchange, null);
		verify(secondMatcher, never()).matches(this.exchange);
	}

	@Test
	public void handleWhenSecondMatchesThenOnlySecondInvoked() {
		ServerAccessDeniedHandler firstHandler = mock(ServerAccessDeniedHandler.class);
		ServerWebExchangeMatcher firstMatcher = mock(ServerWebExchangeMatcher.class);
		ServerAccessDeniedHandler secondHandler = mock(ServerAccessDeniedHandler.class);
		ServerWebExchangeMatcher secondMatcher = mock(ServerWebExchangeMatcher.class);
		given(firstMatcher.matches(this.exchange)).willReturn(MatchResult.notMatch());
		given(secondMatcher.matches(this.exchange)).willReturn(MatchResult.match());
		given(firstHandler.handle(this.exchange, null)).willReturn(Mono.empty());
		given(secondHandler.handle(this.exchange, null)).willReturn(Mono.empty());
		this.entries.add(new DelegateEntry(firstMatcher, firstHandler));
		this.entries.add(new DelegateEntry(secondMatcher, secondHandler));
		this.delegator = new ServerWebExchangeDelegatingServerAccessDeniedHandler(this.entries);
		this.delegator.handle(this.exchange, null).block();
		verify(secondHandler).handle(this.exchange, null);
		verify(firstHandler, never()).handle(this.exchange, null);
		verify(this.accessDeniedHandler, never()).handle(this.exchange, null);
	}

}
