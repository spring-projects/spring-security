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

import java.util.Arrays;
import java.util.List;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * A {@link ServerAccessDeniedHandler} which delegates to multiple {@link ServerAccessDeniedHandler}s based
 * on a {@link ServerWebExchangeMatcher}
 *
 * @author Josh Cummings
 * @since 5.1
 */
public class ServerWebExchangeDelegatingServerAccessDeniedHandler
	implements ServerAccessDeniedHandler {

	private final List<DelegateEntry> handlers;

	private ServerAccessDeniedHandler defaultHandler = (exchange, e) -> {
		exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
		return exchange.getResponse().setComplete();
	};

	/**
	 * Creates a new instance
	 *
	 * @param handlers a list of {@link ServerWebExchangeMatcher}/
	 * {@link ServerAccessDeniedHandler} pairs that should be used. Each is considered
	 * in the order they are specified and only the first {@link ServerAccessDeniedHandler}
	 * is used. If none match, then the default {@link ServerAccessDeniedHandler}
	 * is used.
	 */
	public ServerWebExchangeDelegatingServerAccessDeniedHandler(
			DelegateEntry... handlers) {
		this(Arrays.asList(handlers));
	}

	/**
	 * Creates a new instance
	 *
	 * @param handlers a list of {@link ServerWebExchangeMatcher}/
	 * {@link ServerAccessDeniedHandler} pairs that should be used. Each is considered
	 * in the order they are specified and only the first {@link ServerAccessDeniedHandler}
	 * is used. If none match, then the default {@link ServerAccessDeniedHandler}
	 * is used.
	 */
	public ServerWebExchangeDelegatingServerAccessDeniedHandler(
			List<DelegateEntry> handlers) {
		Assert.notEmpty(handlers, "handlers cannot be null");
		this.handlers = handlers;
	}

	@Override
	public Mono<Void> handle(ServerWebExchange exchange,
		AccessDeniedException denied) {
		return Flux.fromIterable(this.handlers)
				.filterWhen(entry -> isMatch(exchange, entry))
				.next()
				.map(DelegateEntry::getAccessDeniedHandler)
				.defaultIfEmpty(this.defaultHandler)
				.flatMap(handler -> handler.handle(exchange, denied));
	}

	/**
	 * Use this {@link ServerAccessDeniedHandler} when no {@link ServerWebExchangeMatcher}
	 * matches.
	 *
	 * @param accessDeniedHandler - the default {@link ServerAccessDeniedHandler} to use
	 */
	public void setDefaultAccessDeniedHandler(ServerAccessDeniedHandler accessDeniedHandler) {
		Assert.notNull(accessDeniedHandler, "accessDeniedHandler cannot be null");
		this.defaultHandler = accessDeniedHandler;
	}

	public static class DelegateEntry {
		private final ServerWebExchangeMatcher matcher;
		private final ServerAccessDeniedHandler accessDeniedHandler;

		public DelegateEntry(ServerWebExchangeMatcher matcher,
				ServerAccessDeniedHandler accessDeniedHandler) {
			this.matcher = matcher;
			this.accessDeniedHandler = accessDeniedHandler;
		}

		public ServerWebExchangeMatcher getMatcher() {
			return this.matcher;
		}

		public ServerAccessDeniedHandler getAccessDeniedHandler() {
			return this.accessDeniedHandler;
		}
	}

	private Mono<Boolean> isMatch(ServerWebExchange exchange, DelegateEntry entry) {
		ServerWebExchangeMatcher matcher = entry.getMatcher();
		return matcher.matches(exchange)
				.map(ServerWebExchangeMatcher.MatchResult::isMatch);
	}
}
