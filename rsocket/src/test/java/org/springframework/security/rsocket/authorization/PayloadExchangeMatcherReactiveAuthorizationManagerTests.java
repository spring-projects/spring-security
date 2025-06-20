/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.rsocket.authorization;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.rsocket.api.PayloadExchange;
import org.springframework.security.rsocket.util.matcher.PayloadExchangeAuthorizationContext;
import org.springframework.security.rsocket.util.matcher.PayloadExchangeMatcher;
import org.springframework.security.rsocket.util.matcher.PayloadExchangeMatcherEntry;
import org.springframework.security.rsocket.util.matcher.PayloadExchangeMatchers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

/**
 * @author Rob Winch
 */
@ExtendWith(MockitoExtension.class)
public class PayloadExchangeMatcherReactiveAuthorizationManagerTests {

	@Mock
	private ReactiveAuthorizationManager<PayloadExchangeAuthorizationContext> authz;

	@Mock
	private ReactiveAuthorizationManager<PayloadExchangeAuthorizationContext> authz2;

	@Mock
	private PayloadExchange exchange;

	@Test
	public void checkWhenGrantedThenGranted() {
		AuthorizationDecision expected = new AuthorizationDecision(true);
		given(this.authz.check(any(), any())).willReturn(Mono.just(expected));
		given(this.authz.authorize(any(), any())).willCallRealMethod();
		PayloadExchangeMatcherReactiveAuthorizationManager manager = PayloadExchangeMatcherReactiveAuthorizationManager
			.builder()
			.add(new PayloadExchangeMatcherEntry<>(PayloadExchangeMatchers.anyExchange(), this.authz))
			.build();
		assertThat(manager.check(Mono.empty(), this.exchange).block()).isEqualTo(expected);
	}

	@Test
	public void checkWhenDeniedThenDenied() {
		AuthorizationDecision expected = new AuthorizationDecision(false);
		given(this.authz.check(any(), any())).willReturn(Mono.just(expected));
		given(this.authz.authorize(any(), any())).willCallRealMethod();
		PayloadExchangeMatcherReactiveAuthorizationManager manager = PayloadExchangeMatcherReactiveAuthorizationManager
			.builder()
			.add(new PayloadExchangeMatcherEntry<>(PayloadExchangeMatchers.anyExchange(), this.authz))
			.build();
		assertThat(manager.check(Mono.empty(), this.exchange).block()).isEqualTo(expected);
	}

	@Test
	public void checkWhenFirstMatchThenSecondUsed() {
		AuthorizationDecision expected = new AuthorizationDecision(true);
		given(this.authz.check(any(), any())).willReturn(Mono.just(expected));
		given(this.authz.authorize(any(), any())).willCallRealMethod();
		PayloadExchangeMatcherReactiveAuthorizationManager manager = PayloadExchangeMatcherReactiveAuthorizationManager
			.builder()
			.add(new PayloadExchangeMatcherEntry<>(PayloadExchangeMatchers.anyExchange(), this.authz))
			.add(new PayloadExchangeMatcherEntry<>((e) -> PayloadExchangeMatcher.MatchResult.notMatch(), this.authz2))
			.build();
		assertThat(manager.check(Mono.empty(), this.exchange).block()).isEqualTo(expected);
	}

	@Test
	public void checkWhenSecondMatchThenSecondUsed() {
		AuthorizationDecision expected = new AuthorizationDecision(true);
		given(this.authz2.check(any(), any())).willReturn(Mono.just(expected));
		given(this.authz2.authorize(any(), any())).willCallRealMethod();
		PayloadExchangeMatcherReactiveAuthorizationManager manager = PayloadExchangeMatcherReactiveAuthorizationManager
			.builder()
			.add(new PayloadExchangeMatcherEntry<>((e) -> PayloadExchangeMatcher.MatchResult.notMatch(), this.authz))
			.add(new PayloadExchangeMatcherEntry<>(PayloadExchangeMatchers.anyExchange(), this.authz2))
			.build();
		assertThat(manager.check(Mono.empty(), this.exchange).block()).isEqualTo(expected);
	}

}
