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
package org.springframework.security.web.server.authorization;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class DelegatingReactiveAuthorizationManager implements ReactiveAuthorizationManager<ServerWebExchange> {
	private final LinkedHashMap<ServerWebExchangeMatcher, ReactiveAuthorizationManager<AuthorizationContext>> mappings;

	private DelegatingReactiveAuthorizationManager(LinkedHashMap<ServerWebExchangeMatcher, ReactiveAuthorizationManager<AuthorizationContext>> mappings) {
		this.mappings = mappings;
	}

	@Override
	public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, ServerWebExchange exchange) {
		for(Map.Entry<ServerWebExchangeMatcher, ReactiveAuthorizationManager<AuthorizationContext>> entry : mappings.entrySet()) {
			ServerWebExchangeMatcher matcher = entry.getKey();
			ServerWebExchangeMatcher.MatchResult match = matcher.matches(exchange);
			if(match.isMatch()) {
				Map<String,Object> variables = match.getVariables();
				AuthorizationContext context = new AuthorizationContext(exchange, variables);
				return entry.getValue().check(authentication, context);
			}
		}
		return Mono.just(new AuthorizationDecision(false));
	}

	public static DelegatingReactiveAuthorizationManager.Builder builder() {
		return new DelegatingReactiveAuthorizationManager.Builder();
	}

	public static class Builder {
		private final LinkedHashMap<ServerWebExchangeMatcher, ReactiveAuthorizationManager<AuthorizationContext>> mappings = new LinkedHashMap<>();

		private Builder() {
		}

		public DelegatingReactiveAuthorizationManager.Builder add(ServerWebExchangeMatcher matcher, ReactiveAuthorizationManager<AuthorizationContext> manager) {
			this.mappings.put(matcher, manager);
			return this;
		}

		public DelegatingReactiveAuthorizationManager build() {
			return new DelegatingReactiveAuthorizationManager(mappings);
		}
	}
}
