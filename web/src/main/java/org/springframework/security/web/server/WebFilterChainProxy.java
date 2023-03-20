/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.web.server;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import jakarta.servlet.FilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.server.handler.DefaultWebFilterChain;

/**
 * Used to delegate to a List of {@link SecurityWebFilterChain} instances.
 *
 * @author Rob Winch
 * @since 5.0
 */
public class WebFilterChainProxy implements WebFilter {

	private final List<SecurityWebFilterChain> filters;

	private WebFilterChainDecorator filterChainDecorator = new DefaultWebFilterChainDecorator();

	public WebFilterChainProxy(List<SecurityWebFilterChain> filters) {
		this.filters = filters;
	}

	public WebFilterChainProxy(SecurityWebFilterChain... filters) {
		this.filters = Arrays.asList(filters);
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		return Flux.fromIterable(this.filters)
				.filterWhen((securityWebFilterChain) -> securityWebFilterChain.matches(exchange)).next()
				.switchIfEmpty(
						Mono.defer(() -> this.filterChainDecorator.decorate(chain).filter(exchange).then(Mono.empty())))
				.flatMap((securityWebFilterChain) -> securityWebFilterChain.getWebFilters().collectList())
				.map((filters) -> this.filterChainDecorator.decorate(chain, filters))
				.flatMap((securedChain) -> securedChain.filter(exchange));
	}

	/**
	 * Used to decorate the original {@link FilterChain} for each request
	 *
	 * <p>
	 * By default, this decorates the filter chain with a {@link DefaultWebFilterChain}
	 * that iterates through security filters and then delegates to the original chain
	 * @param filterChainDecorator the strategy for constructing the filter chain
	 * @since 6.0
	 */
	public void setFilterChainDecorator(WebFilterChainDecorator filterChainDecorator) {
		Assert.notNull(filterChainDecorator, "filterChainDecorator cannot be null");
		this.filterChainDecorator = filterChainDecorator;
	}

	/**
	 * A strategy for decorating the provided filter chain with one that accounts for the
	 * {@link SecurityFilterChain} for a given request.
	 *
	 * @author Josh Cummings
	 * @since 6.0
	 */
	public interface WebFilterChainDecorator {

		/**
		 * Provide a new {@link FilterChain} that accounts for needed security
		 * considerations when there are no security filters.
		 * @param original the original {@link FilterChain}
		 * @return a security-enabled {@link FilterChain}
		 */
		default WebFilterChain decorate(WebFilterChain original) {
			return decorate(original, Collections.emptyList());
		}

		/**
		 * Provide a new {@link FilterChain} that accounts for the provided filters as
		 * well as teh original filter chain.
		 * @param original the original {@link FilterChain}
		 * @param filters the security filters
		 * @return a security-enabled {@link FilterChain} that includes the provided
		 * filters
		 */
		WebFilterChain decorate(WebFilterChain original, List<WebFilter> filters);

	}

	/**
	 * A {@link WebFilterChainDecorator} that uses the {@link DefaultWebFilterChain}
	 *
	 * @author Josh Cummings
	 * @since 6.0
	 */
	public static class DefaultWebFilterChainDecorator implements WebFilterChainDecorator {

		/**
		 * {@inheritDoc}
		 */
		@Override
		public WebFilterChain decorate(WebFilterChain original) {
			return original;
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public WebFilterChain decorate(WebFilterChain original, List<WebFilter> filters) {
			return new DefaultWebFilterChain(original::filter, filters);
		}

	}

}
