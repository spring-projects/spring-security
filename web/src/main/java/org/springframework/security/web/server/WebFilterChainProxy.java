/*
 * Copyright 2002-2021 the original author or authors.
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
import java.util.List;
import java.util.function.BiFunction;

import io.micrometer.common.KeyValues;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationConvention;
import io.micrometer.observation.ObservationRegistry;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.server.WebHandler;
import org.springframework.web.server.handler.DefaultWebFilterChain;

/**
 * Used to delegate to a List of {@link SecurityWebFilterChain} instances.
 *
 * @author Rob Winch
 * @since 5.0
 */
public class WebFilterChainProxy implements WebFilter {

	private static final BiFunction<WebHandler, List<WebFilter>, WebFilterChain> DEFAULT_CHAIN = DefaultWebFilterChain::new;

	private final List<SecurityWebFilterChain> filters;

	private BiFunction<WebHandler, List<WebFilter>, WebFilterChain> chain = DEFAULT_CHAIN;

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
				.switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
				.flatMap((securityWebFilterChain) -> securityWebFilterChain.getWebFilters().collectList())
				.map((filters) -> this.chain.apply(chain::filter, filters))
				.flatMap((securedChain) -> securedChain.filter(exchange));
	}

	/**
	 * Sets the {@link ObservationRegistry} to use.
	 * Use {@link ObservationRegistry#NOOP} to turn off observations.
	 *
	 * @param observationRegistry the {@link ObservationRegistry} to use
	 * @since 6.0
	 */
	public void setObservationRegistry(ObservationRegistry observationRegistry) {
		Assert.notNull(observationRegistry, "observationRegistry cannot be null");
		if (!observationRegistry.isNoop()) {
			this.chain = DEFAULT_CHAIN.andThen((chain) -> new ObservationWebFilterChain(observationRegistry, chain));
		}
		else {
			this.chain = DEFAULT_CHAIN;
		}
	}

	private final class ObservationWebFilterChain implements WebFilterChain {

		private static final String OBSERVATION_NAME = "spring.security.filter.chain";

		private final ObservationRegistry registry;

		private final WebFilterChain delegate;

		private FilterChainObservationConvention observationConvention = new FilterChainObservationConvention();

		public ObservationWebFilterChain(ObservationRegistry registry, WebFilterChain delegate) {
			this.registry = registry;
			this.delegate = delegate;
		}

		@Override
		public Mono<Void> filter(ServerWebExchange exchange) {
			FilterChainObservationContext context = new FilterChainObservationContext(exchange);
			Observation observation = Observation.createNotStarted(OBSERVATION_NAME, context, this.registry)
					.observationConvention(this.observationConvention).start();
			return this.delegate.filter(exchange).doOnSuccess((v) -> observation.stop()).doOnCancel(observation::stop)
					.doOnError((t) -> {
						observation.error(t);
						observation.stop();
					});
		}

		private static class FilterChainObservationContext extends Observation.Context {

			private final ServerWebExchange exchange;

			private FilterChainObservationContext(ServerWebExchange exchange) {
				this.exchange = exchange;
			}

			String getRequestLine() {
				return this.exchange.getRequest().getPath().toString();
			}

		}

		private static class FilterChainObservationConvention
				implements ObservationConvention<FilterChainObservationContext> {

			@Override
			public KeyValues getHighCardinalityKeyValues(FilterChainObservationContext context) {
				String requestLine = context.getRequestLine();
				return KeyValues.of("request.line", requestLine);
			}

			@Override
			public boolean supportsContext(Observation.Context context) {
				return context instanceof FilterChainObservationContext;
			}

		}

	}

}
