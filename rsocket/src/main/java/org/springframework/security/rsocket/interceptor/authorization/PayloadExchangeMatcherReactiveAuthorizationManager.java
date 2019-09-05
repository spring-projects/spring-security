/*
 * Copyright 2019 the original author or authors.
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

package org.springframework.security.rsocket.interceptor.authorization;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import org.springframework.security.rsocket.interceptor.PayloadExchange;
import org.springframework.security.rsocket.util.PayloadExchangeAuthorizationContext;
import org.springframework.security.rsocket.util.PayloadExchangeMatcher;
import org.springframework.security.rsocket.util.PayloadExchangeMatcherEntry;

import java.util.ArrayList;
import java.util.List;

/**
 * Maps a @{code List} of {@link PayloadExchangeMatcher} instances to
 * @{code ReactiveAuthorizationManager} instances.
 *
 * @author Rob Winch
 * @since 5.2
 */
public class PayloadExchangeMatcherReactiveAuthorizationManager implements ReactiveAuthorizationManager<PayloadExchange> {
	private final List<PayloadExchangeMatcherEntry<ReactiveAuthorizationManager<PayloadExchangeAuthorizationContext>>> mappings;

	private PayloadExchangeMatcherReactiveAuthorizationManager(List<PayloadExchangeMatcherEntry<ReactiveAuthorizationManager<PayloadExchangeAuthorizationContext>>> mappings) {
		Assert.notEmpty(mappings, "mappings cannot be null");
		this.mappings = mappings;
	}

	@Override
	public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, PayloadExchange exchange) {
		return Flux.fromIterable(this.mappings)
				.concatMap(mapping -> mapping.getMatcher().matches(exchange)
						.filter(PayloadExchangeMatcher.MatchResult::isMatch)
						.map(r -> r.getVariables())
						.flatMap(variables -> mapping.getEntry()
								.check(authentication, new PayloadExchangeAuthorizationContext(exchange, variables))
						)
				)
				.next()
				.switchIfEmpty(Mono.fromCallable(() -> new AuthorizationDecision(false)));
	}

	public static PayloadExchangeMatcherReactiveAuthorizationManager.Builder builder() {
		return new PayloadExchangeMatcherReactiveAuthorizationManager.Builder();
	}

	public static class Builder {
		private final List<PayloadExchangeMatcherEntry<ReactiveAuthorizationManager<PayloadExchangeAuthorizationContext>>> mappings = new ArrayList<>();

		private Builder() {
		}

		public PayloadExchangeMatcherReactiveAuthorizationManager.Builder add(
				PayloadExchangeMatcherEntry<ReactiveAuthorizationManager<PayloadExchangeAuthorizationContext>> entry) {
			this.mappings.add(entry);
			return this;
		}

		public PayloadExchangeMatcherReactiveAuthorizationManager build() {
			return new PayloadExchangeMatcherReactiveAuthorizationManager(this.mappings);
		}
	}
}
