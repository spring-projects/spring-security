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

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcherEntry;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class DelegatingReactiveAuthorizationManager implements ReactiveAuthorizationManager<ServerWebExchange> {
	private final List<ServerWebExchangeMatcherEntry<ReactiveAuthorizationManager<AuthorizationContext>>> mappings;

	private DelegatingReactiveAuthorizationManager(List<ServerWebExchangeMatcherEntry<ReactiveAuthorizationManager<AuthorizationContext>>> mappings) {
		this.mappings = mappings;
	}

	@Override
	public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, ServerWebExchange exchange) {
		return Flux.fromIterable(mappings)
			.concatMap(mapping -> mapping.getMatcher().matches(exchange)
				.filter(ServerWebExchangeMatcher.MatchResult::isMatch)
				.map(r -> r.getVariables())
				.flatMap(variables -> mapping.getEntry()
					.check(authentication, new AuthorizationContext(exchange, variables))
				)
			)
			.next()
			.defaultIfEmpty(new AuthorizationDecision(false));
	}

	public static DelegatingReactiveAuthorizationManager.Builder builder() {
		return new DelegatingReactiveAuthorizationManager.Builder();
	}

	public static class Builder {
		private final List<ServerWebExchangeMatcherEntry<ReactiveAuthorizationManager<AuthorizationContext>>> mappings = new ArrayList<>();

		private Builder() {
		}

		public DelegatingReactiveAuthorizationManager.Builder add(ServerWebExchangeMatcherEntry<ReactiveAuthorizationManager<AuthorizationContext>> entry) {
			this.mappings.add(entry);
			return this;
		}

		public DelegatingReactiveAuthorizationManager build() {
			return new DelegatingReactiveAuthorizationManager(mappings);
		}
	}
}
