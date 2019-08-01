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
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.authorization.AuthorityReactiveAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcherEntry;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class DelegatingReactiveAuthorizationManagerTests {
	@Mock
	ServerWebExchangeMatcher match1;
	@Mock
	ServerWebExchangeMatcher match2;
	@Mock AuthorityReactiveAuthorizationManager<AuthorizationContext> delegate1;
	@Mock AuthorityReactiveAuthorizationManager<AuthorizationContext> delegate2;
	@Mock
	ServerWebExchange exchange;
	@Mock
	Mono<Authentication> authentication;
	@Mock
	AuthorizationDecision decision;

	DelegatingReactiveAuthorizationManager manager;

	@Before
	public void setup() {
		manager = DelegatingReactiveAuthorizationManager.builder()
			.add(new ServerWebExchangeMatcherEntry<>(match1, delegate1))
			.add(new ServerWebExchangeMatcherEntry<>(match2, delegate2))
			.build();
	}

	@Test
	public void checkWhenFirstMatchesThenNoMoreMatchersAndNoMoreDelegatesInvoked() {
		when(match1.matches(any())).thenReturn(ServerWebExchangeMatcher.MatchResult.match());
		when(delegate1.check(eq(authentication), any(AuthorizationContext.class))).thenReturn(Mono.just(decision));

		assertThat(manager.check(authentication, exchange).block()).isEqualTo(decision);

		verifyZeroInteractions(match2, delegate2);
	}

	@Test
	public void checkWhenSecondMatchesThenNoMoreMatchersAndNoMoreDelegatesInvoked() {
		when(match1.matches(any())).thenReturn(ServerWebExchangeMatcher.MatchResult.notMatch());
		when(match2.matches(any())).thenReturn(ServerWebExchangeMatcher.MatchResult.match());
		when(delegate2.check(eq(authentication), any(AuthorizationContext.class))).thenReturn(Mono.just(decision));

		assertThat(manager.check(authentication, exchange).block()).isEqualTo(decision);

		verifyZeroInteractions(delegate1);
	}
}
