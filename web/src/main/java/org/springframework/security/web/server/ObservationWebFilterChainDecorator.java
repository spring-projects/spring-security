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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.concurrent.atomic.AtomicReference;

import io.micrometer.common.KeyValues;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationConvention;
import io.micrometer.observation.ObservationRegistry;
import reactor.core.publisher.Mono;

import org.springframework.lang.Nullable;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.server.WebHandler;

/**
 * A
 * {@link org.springframework.security.web.server.WebFilterChainProxy.WebFilterChainDecorator}
 * that wraps the chain in before and after observations
 *
 * @author Josh Cummings
 * @since 6.0
 */
public final class ObservationWebFilterChainDecorator implements WebFilterChainProxy.WebFilterChainDecorator {

	private static final String ATTRIBUTE = ObservationWebFilterChainDecorator.class + ".observation";

	static final String UNSECURED_OBSERVATION_NAME = "spring.security.http.unsecured.requests";

	static final String SECURED_OBSERVATION_NAME = "spring.security.http.secured.requests";

	private final ObservationRegistry registry;

	public ObservationWebFilterChainDecorator(ObservationRegistry registry) {
		this.registry = registry;
	}

	@Override
	public WebFilterChain decorate(WebFilterChain original) {
		return wrapUnsecured(original);
	}

	@Override
	public WebFilterChain decorate(WebFilterChain original, List<WebFilter> filters) {
		return new ObservationWebFilterChain(wrapSecured(original)::filter, wrap(filters));
	}

	private static AroundWebFilterObservation observation(ServerWebExchange exchange) {
		return exchange.getAttribute(ATTRIBUTE);
	}

	private WebFilterChain wrapSecured(WebFilterChain original) {
		return (exchange) -> {
			AroundWebFilterObservation parent = observation(exchange);
			Observation observation = Observation.createNotStarted(SECURED_OBSERVATION_NAME, this.registry)
					.contextualName("secured request");
			return parent.wrap(WebFilterObservation.create(observation).wrap(original)).filter(exchange);
		};
	}

	private WebFilterChain wrapUnsecured(WebFilterChain original) {
		return (exchange) -> {
			Observation observation = Observation.createNotStarted(UNSECURED_OBSERVATION_NAME, this.registry)
					.contextualName("unsecured request");
			return WebFilterObservation.create(observation).wrap(original).filter(exchange);
		};
	}

	private List<ObservationWebFilter> wrap(List<WebFilter> filters) {
		int size = filters.size();
		List<ObservationWebFilter> observableFilters = new ArrayList<>();
		int position = 1;
		for (WebFilter filter : filters) {
			observableFilters.add(new ObservationWebFilter(this.registry, filter, position, size));
			position++;
		}
		return observableFilters;
	}

	static class ObservationWebFilterChain implements WebFilterChain {

		private final WebHandler handler;

		@Nullable
		private final ObservationWebFilter currentFilter;

		@Nullable
		private final ObservationWebFilterChain chain;

		/**
		 * Public constructor with the list of filters and the target handler to use.
		 * @param handler the target handler
		 * @param filters the filters ahead of the handler
		 * @since 5.1
		 */
		ObservationWebFilterChain(WebHandler handler, List<ObservationWebFilter> filters) {
			Assert.notNull(handler, "WebHandler is required");
			this.handler = handler;
			ObservationWebFilterChain chain = initChain(filters, handler);
			this.currentFilter = chain.currentFilter;
			this.chain = chain.chain;
		}

		private static ObservationWebFilterChain initChain(List<ObservationWebFilter> filters, WebHandler handler) {
			ObservationWebFilterChain chain = new ObservationWebFilterChain(handler, null, null);
			ListIterator<? extends ObservationWebFilter> iterator = filters.listIterator(filters.size());
			while (iterator.hasPrevious()) {
				chain = new ObservationWebFilterChain(handler, iterator.previous(), chain);
			}
			return chain;
		}

		/**
		 * Private constructor to represent one link in the chain.
		 */
		private ObservationWebFilterChain(WebHandler handler, @Nullable ObservationWebFilter currentFilter,
				@Nullable ObservationWebFilterChain chain) {
			this.currentFilter = currentFilter;
			this.handler = handler;
			this.chain = chain;
		}

		@Override
		public Mono<Void> filter(ServerWebExchange exchange) {
			return Mono.defer(() -> (this.currentFilter != null && this.chain != null)
					? invokeFilter(this.currentFilter, this.chain, exchange) : this.handler.handle(exchange));
		}

		private Mono<Void> invokeFilter(ObservationWebFilter current, ObservationWebFilterChain chain,
				ServerWebExchange exchange) {
			String currentName = current.getName();
			return current.filter(exchange, chain).checkpoint(currentName + " [DefaultWebFilterChain]");
		}

	}

	static final class ObservationWebFilter implements WebFilter {

		private final ObservationRegistry registry;

		private final WebFilterChainObservationConvention convention = new WebFilterChainObservationConvention();

		private final WebFilter filter;

		private final String name;

		private final int position;

		private final int size;

		ObservationWebFilter(ObservationRegistry registry, WebFilter filter, int position, int size) {
			this.registry = registry;
			this.filter = filter;
			this.name = filter.getClass().getSimpleName();
			this.position = position;
			this.size = size;
		}

		String getName() {
			return this.name;
		}

		@Override
		public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
			if (this.position == 1) {
				AroundWebFilterObservation parent = parent(exchange);
				return parent.wrap(this::wrapFilter).filter(exchange, chain);
			}
			else {
				return wrapFilter(exchange, chain);
			}
		}

		private Mono<Void> wrapFilter(ServerWebExchange exchange, WebFilterChain chain) {
			AroundWebFilterObservation parent = observation(exchange);
			WebFilterChainObservationContext parentBefore = (WebFilterChainObservationContext) parent.before()
					.getContext();
			parentBefore.setChainSize(this.size);
			parentBefore.setFilterName(this.name);
			parentBefore.setChainPosition(this.position);
			return this.filter.filter(exchange, chain).doOnSuccess((result) -> {
				parent.start();
				WebFilterChainObservationContext parentAfter = (WebFilterChainObservationContext) parent.after()
						.getContext();
				parentAfter.setChainSize(this.size);
				parentAfter.setFilterName(this.name);
				parentAfter.setChainPosition(this.size - this.position + 1);
			});
		}

		private AroundWebFilterObservation parent(ServerWebExchange exchange) {
			WebFilterChainObservationContext beforeContext = WebFilterChainObservationContext.before();
			WebFilterChainObservationContext afterContext = WebFilterChainObservationContext.after();
			Observation before = Observation.createNotStarted(this.convention, () -> beforeContext, this.registry);
			Observation after = Observation.createNotStarted(this.convention, () -> afterContext, this.registry);
			AroundWebFilterObservation parent = AroundWebFilterObservation.create(before, after);
			exchange.getAttributes().put(ATTRIBUTE, parent);
			return parent;
		}

	}

	interface AroundWebFilterObservation extends WebFilterObservation {

		AroundWebFilterObservation NOOP = new AroundWebFilterObservation() {
		};

		static AroundWebFilterObservation create(Observation before, Observation after) {
			if (before.isNoop() || after.isNoop()) {
				return NOOP;
			}
			return new SimpleAroundWebFilterObservation(before, after);
		}

		default Observation before() {
			return Observation.NOOP;
		}

		default Observation after() {
			return Observation.NOOP;
		}

		class SimpleAroundWebFilterObservation implements AroundWebFilterObservation {

			private final Iterator<Observation> observations;

			private final Observation before;

			private final Observation after;

			private final AtomicReference<Observation> currentObservation = new AtomicReference<>(null);

			SimpleAroundWebFilterObservation(Observation before, Observation after) {
				this.before = before;
				this.after = after;
				this.observations = Arrays.asList(before, after).iterator();
			}

			@Override
			public void start() {
				if (this.observations.hasNext()) {
					stop();
					Observation observation = this.observations.next();
					observation.start();
					this.currentObservation.set(observation);
				}
			}

			@Override
			public void error(Throwable ex) {
				Observation observation = this.currentObservation.get();
				if (observation == null) {
					return;
				}
				observation.error(ex);
			}

			@Override
			public void stop() {
				Observation observation = this.currentObservation.getAndSet(null);
				if (observation == null) {
					return;
				}
				observation.stop();
			}

			@Override
			public WebFilterChain wrap(WebFilterChain chain) {
				return (exchange) -> {
					stop();
					// @formatter:off
					return chain.filter(exchange)
							.doOnSuccess((v) -> start())
							.doOnCancel(this::start)
							.doOnError((t) -> {
								error(t);
								start();
							});
					// @formatter:on
				};
			}

			@Override
			public WebFilter wrap(WebFilter filter) {
				return (exchange, chain) -> {
					start();
					// @formatter:off
					return filter.filter(exchange, chain)
							.doOnSuccess((v) -> stop())
							.doOnCancel(this::stop)
							.doOnError((t) -> {
								error(t);
								stop();
							});
					// @formatter:on
				};
			}

			@Override
			public Observation before() {
				return this.before;
			}

			@Override
			public Observation after() {
				return this.after;
			}

		}

	}

	interface WebFilterObservation {

		WebFilterObservation NOOP = new WebFilterObservation() {
		};

		static WebFilterObservation create(Observation observation) {
			if (observation.isNoop()) {
				return NOOP;
			}
			return new SimpleWebFilterObservation(observation);
		}

		default void start() {
		}

		default void error(Throwable ex) {
		}

		default void stop() {
		}

		default WebFilter wrap(WebFilter filter) {
			return filter;
		}

		default WebFilterChain wrap(WebFilterChain chain) {
			return chain;
		}

		class SimpleWebFilterObservation implements WebFilterObservation {

			private final Observation observation;

			SimpleWebFilterObservation(Observation observation) {
				this.observation = observation;
			}

			@Override
			public void start() {
				this.observation.start();
			}

			@Override
			public void error(Throwable ex) {
				this.observation.error(ex);
			}

			@Override
			public void stop() {
				this.observation.stop();
			}

			@Override
			public WebFilter wrap(WebFilter filter) {
				if (this.observation.isNoop()) {
					return filter;
				}
				return (exchange, chain) -> {
					this.observation.start();
					return filter.filter(exchange, chain).doOnSuccess((v) -> this.observation.stop())
							.doOnCancel(this.observation::stop).doOnError((t) -> {
								this.observation.error(t);
								this.observation.stop();
							});
				};
			}

			@Override
			public WebFilterChain wrap(WebFilterChain chain) {
				if (this.observation.isNoop()) {
					return chain;
				}
				return (exchange) -> {
					this.observation.start();
					return chain.filter(exchange).doOnSuccess((v) -> this.observation.stop())
							.doOnCancel(this.observation::stop).doOnError((t) -> {
								this.observation.error(t);
								this.observation.stop();
							});
				};
			}

		}

	}

	static final class WebFilterChainObservationContext extends Observation.Context {

		private final String filterSection;

		private String filterName;

		private int chainPosition;

		private int chainSize;

		private WebFilterChainObservationContext(String filterSection) {
			this.filterSection = filterSection;
		}

		static WebFilterChainObservationContext before() {
			return new WebFilterChainObservationContext("before");
		}

		static WebFilterChainObservationContext after() {
			return new WebFilterChainObservationContext("after");
		}

		String getFilterSection() {
			return this.filterSection;
		}

		String getFilterName() {
			return this.filterName;
		}

		void setFilterName(String filterName) {
			this.filterName = filterName;
		}

		int getChainPosition() {
			return this.chainPosition;
		}

		void setChainPosition(int chainPosition) {
			this.chainPosition = chainPosition;
		}

		int getChainSize() {
			return this.chainSize;
		}

		void setChainSize(int chainSize) {
			this.chainSize = chainSize;
		}

	}

	static final class WebFilterChainObservationConvention
			implements ObservationConvention<WebFilterChainObservationContext> {

		static final String CHAIN_OBSERVATION_NAME = "spring.security.filterchains";

		private static final String CHAIN_POSITION_NAME = "spring.security.filterchain.position";

		private static final String CHAIN_SIZE_NAME = "spring.security.filterchain.size";

		private static final String FILTER_SECTION_NAME = "spring.security.reached.filter.section";

		private static final String FILTER_NAME = "spring.security.reached.filter.name";

		@Override
		public String getName() {
			return CHAIN_OBSERVATION_NAME;
		}

		@Override
		public String getContextualName(WebFilterChainObservationContext context) {
			return "security filterchain " + context.getFilterSection();
		}

		@Override
		public KeyValues getLowCardinalityKeyValues(WebFilterChainObservationContext context) {
			KeyValues kv = KeyValues.of(CHAIN_SIZE_NAME, String.valueOf(context.getChainSize()))
					.and(CHAIN_POSITION_NAME, String.valueOf(context.getChainPosition()))
					.and(FILTER_SECTION_NAME, context.getFilterSection());
			if (context.getFilterName() != null) {
				kv = kv.and(FILTER_NAME, context.getFilterName());
			}
			return kv;
		}

		@Override
		public boolean supportsContext(Observation.Context context) {
			return context instanceof WebFilterChainObservationContext;
		}

	}

}
