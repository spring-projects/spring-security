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

package org.springframework.security.web.server.authorization;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import reactor.core.publisher.Mono;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authorization.AuthorityReactiveAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcherEntry;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verifyZeroInteractions;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class DelegatingReactiveAuthorizationManagerTests {

	@Mock
	ServerWebExchangeMatcher match1;

	@Mock
	ServerWebExchangeMatcher match2;

	@Mock
	AuthorityReactiveAuthorizationManager<AuthorizationContext> delegate1;

	@Mock
	AuthorityReactiveAuthorizationManager<AuthorizationContext> delegate2;

	ServerWebExchange exchange;

	@Mock
	Mono<Authentication> authentication;

	@Mock
	AuthorizationDecision decision;

	DelegatingReactiveAuthorizationManager manager;

	@Before
	public void setup() {
		MockitoAnnotations.initMocks(this);
		this.manager = DelegatingReactiveAuthorizationManager.builder()
				.add(new ServerWebExchangeMatcherEntry<>(this.match1, this.delegate1))
				.add(new ServerWebExchangeMatcherEntry<>(this.match2, this.delegate2)).build();
		MockServerHttpRequest request = MockServerHttpRequest.get("/test").build();
		this.exchange = MockServerWebExchange.from(request);
	}

	@Test
	public void checkWhenFirstMatchesThenNoMoreMatchersAndNoMoreDelegatesInvoked() {
		given(this.match1.matches(any())).willReturn(ServerWebExchangeMatcher.MatchResult.match());
		given(this.delegate1.check(eq(this.authentication), any(AuthorizationContext.class)))
				.willReturn(Mono.just(this.decision));

		assertThat(this.manager.check(this.authentication, this.exchange).block()).isEqualTo(this.decision);

		verifyZeroInteractions(this.match2, this.delegate2);
	}

	@Test
	public void checkWhenSecondMatchesThenNoMoreMatchersAndNoMoreDelegatesInvoked() {
		given(this.match1.matches(any())).willReturn(ServerWebExchangeMatcher.MatchResult.notMatch());
		given(this.match2.matches(any())).willReturn(ServerWebExchangeMatcher.MatchResult.match());
		given(this.delegate2.check(eq(this.authentication), any(AuthorizationContext.class)))
				.willReturn(Mono.just(this.decision));

		assertThat(this.manager.check(this.authentication, this.exchange).block()).isEqualTo(this.decision);

		verifyZeroInteractions(this.delegate1);
	}

}
