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
import java.util.List;
import java.util.stream.Stream;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import io.micrometer.observation.ObservationRegistry;
import io.micrometer.observation.contextpropagation.ObservationThreadLocalAccessor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link ObservationWebFilterChainDecorator}
 */
public class ObservationWebFilterChainDecoratorTests {

	@Test
	void decorateWhenDefaultsThenObserves() {
		ObservationHandler<?> handler = mock(ObservationHandler.class);
		given(handler.supportsContext(any())).willReturn(true);
		ObservationRegistry registry = ObservationRegistry.create();
		registry.observationConfig().observationHandler(handler);
		ObservationWebFilterChainDecorator decorator = new ObservationWebFilterChainDecorator(registry);
		WebFilterChain chain = mock(WebFilterChain.class);
		given(chain.filter(any())).willReturn(Mono.empty());
		WebFilterChain decorated = decorator.decorate(chain);
		decorated.filter(MockServerWebExchange.from(MockServerHttpRequest.get("/").build())).block();
		verify(handler).onStart(any());
	}

	@Test
	void decorateWhenNoopThenDoesNotObserve() {
		ObservationHandler<?> handler = mock(ObservationHandler.class);
		given(handler.supportsContext(any())).willReturn(true);
		ObservationRegistry registry = ObservationRegistry.NOOP;
		registry.observationConfig().observationHandler(handler);
		ObservationWebFilterChainDecorator decorator = new ObservationWebFilterChainDecorator(registry);
		WebFilterChain chain = mock(WebFilterChain.class);
		given(chain.filter(any())).willReturn(Mono.empty());
		WebFilterChain decorated = decorator.decorate(chain);
		decorated.filter(MockServerWebExchange.from(MockServerHttpRequest.get("/").build())).block();
		verifyNoInteractions(handler);
	}

	@Test
	void decorateWhenTerminatingFilterThenObserves() {
		AccumulatingObservationHandler handler = new AccumulatingObservationHandler();
		ObservationRegistry registry = ObservationRegistry.create();
		registry.observationConfig().observationHandler(handler);
		ObservationWebFilterChainDecorator decorator = new ObservationWebFilterChainDecorator(registry);
		WebFilterChain chain = mock(WebFilterChain.class);
		given(chain.filter(any())).willReturn(Mono.error(() -> new Exception("ack")));
		WebFilterChain decorated = decorator.decorate(chain,
				List.of(new BasicAuthenticationFilter(), new TerminatingFilter()));
		Observation http = Observation.start("http", registry).contextualName("http");
		try {
			decorated.filter(MockServerWebExchange.from(MockServerHttpRequest.get("/").build()))
				.contextWrite((context) -> context.put(ObservationThreadLocalAccessor.KEY, http))
				.block();
		}
		catch (Exception ex) {
			http.error(ex);
		}
		finally {
			http.stop();
		}
		handler.assertSpanStart(0, "http", null);
		handler.assertSpanStart(1, "spring.security.filterchains", "http");
		handler.assertSpanStop(2, "security filterchain before");
		handler.assertSpanStart(3, "spring.security.filterchains", "http");
		handler.assertSpanStop(4, "security filterchain after");
		handler.assertSpanStop(5, "http");
	}

	@Test
	void decorateWhenFilterErrorThenStopsObservation() {
		AccumulatingObservationHandler handler = new AccumulatingObservationHandler();
		ObservationRegistry registry = ObservationRegistry.create();
		registry.observationConfig().observationHandler(handler);
		ObservationWebFilterChainDecorator decorator = new ObservationWebFilterChainDecorator(registry);
		WebFilterChain chain = mock(WebFilterChain.class);
		WebFilterChain decorated = decorator.decorate(chain, List.of(new ErroringFilter()));
		Observation http = Observation.start("http", registry).contextualName("http");
		try {
			decorated.filter(MockServerWebExchange.from(MockServerHttpRequest.get("/").build()))
				.contextWrite((context) -> context.put(ObservationThreadLocalAccessor.KEY, http))
				.block();
		}
		catch (Exception ex) {
			http.error(ex);
		}
		finally {
			http.stop();
		}
		handler.assertSpanStart(0, "http", null);
		handler.assertSpanStart(1, "spring.security.filterchains", "http");
		handler.assertSpanError(2);
		handler.assertSpanStop(3, "security filterchain before");
		handler.assertSpanError(4);
		handler.assertSpanStop(5, "http");
	}

	@Test
	void decorateWhenErrorSignalThenStopsObservation() {
		AccumulatingObservationHandler handler = new AccumulatingObservationHandler();
		ObservationRegistry registry = ObservationRegistry.create();
		registry.observationConfig().observationHandler(handler);
		ObservationWebFilterChainDecorator decorator = new ObservationWebFilterChainDecorator(registry);
		WebFilterChain chain = mock(WebFilterChain.class);
		given(chain.filter(any())).willReturn(Mono.error(() -> new Exception("ack")));
		WebFilterChain decorated = decorator.decorate(chain, List.of(new BasicAuthenticationFilter()));
		Observation http = Observation.start("http", registry).contextualName("http");
		try {
			decorated.filter(MockServerWebExchange.from(MockServerHttpRequest.get("/").build()))
				.contextWrite((context) -> context.put(ObservationThreadLocalAccessor.KEY, http))
				.block();
		}
		catch (Exception ex) {
			http.error(ex);
		}
		finally {
			http.stop();
		}
		handler.assertSpanStart(0, "http", null);
		handler.assertSpanStart(1, "spring.security.filterchains", "http");
		handler.assertSpanStop(2, "security filterchain before");
		handler.assertSpanStart(3, "secured request", "security filterchain before");
		handler.assertSpanError(4);
		handler.assertSpanStop(5, "secured request");
		handler.assertSpanStart(6, "spring.security.filterchains", "http");
		handler.assertSpanError(7);
		handler.assertSpanStop(8, "security filterchain after");
		handler.assertSpanError(9);
		handler.assertSpanStop(10, "http");
	}

	// gh-12849
	@Test
	void decorateWhenCustomAfterFilterThenObserves() {
		AccumulatingObservationHandler handler = new AccumulatingObservationHandler();
		ObservationRegistry registry = ObservationRegistry.create();
		registry.observationConfig().observationHandler(handler);
		ObservationWebFilterChainDecorator decorator = new ObservationWebFilterChainDecorator(registry);
		WebFilter mock = mock(WebFilter.class);
		given(mock.filter(any(), any())).willReturn(Mono.empty());
		WebFilterChain chain = mock(WebFilterChain.class);
		given(chain.filter(any())).willReturn(Mono.empty());
		WebFilterChain decorated = decorator.decorate(chain,
				List.of((e, c) -> c.filter(e).then(Mono.deferContextual((context) -> {
					Observation parentObservation = context.getOrDefault(ObservationThreadLocalAccessor.KEY, null);
					Observation observation = Observation.createNotStarted("custom", registry)
						.parentObservation(parentObservation)
						.contextualName("custom")
						.start();
					return Mono.just("3")
						.doOnSuccess((v) -> observation.stop())
						.doOnCancel(observation::stop)
						.doOnError((t) -> {
							observation.error(t);
							observation.stop();
						})
						.then(Mono.empty());
				}))));
		Observation http = Observation.start("http", registry).contextualName("http");
		try {
			decorated.filter(MockServerWebExchange.from(MockServerHttpRequest.get("/").build()))
				.contextWrite((context) -> context.put(ObservationThreadLocalAccessor.KEY, http))
				.block();
		}
		finally {
			http.stop();
		}
		handler.assertSpanStart(0, "http", null);
		handler.assertSpanStart(1, "spring.security.filterchains", "http");
		handler.assertSpanStop(2, "security filterchain before");
		handler.assertSpanStart(3, "secured request", "security filterchain before");
		handler.assertSpanStop(4, "secured request");
		handler.assertSpanStart(5, "spring.security.filterchains", "http");
		handler.assertSpanStart(6, "custom", "spring.security.filterchains");
		handler.assertSpanStop(7, "custom");
		handler.assertSpanStop(8, "security filterchain after");
		handler.assertSpanStop(9, "http");
	}

	@ParameterizedTest
	@MethodSource("decorateFiltersWhenCompletesThenHasSpringSecurityReachedFilterNameTagArguments")
	void decorateFiltersWhenCompletesThenHasSpringSecurityReachedFilterNameTag(WebFilter filter,
			String expectedFilterNameTag) {
		ObservationHandler<Observation.Context> handler = mock(ObservationHandler.class);
		given(handler.supportsContext(any())).willReturn(true);
		ObservationRegistry registry = ObservationRegistry.create();
		registry.observationConfig().observationHandler(handler);
		ObservationWebFilterChainDecorator decorator = new ObservationWebFilterChainDecorator(registry);
		WebFilterChain chain = mock(WebFilterChain.class);
		given(chain.filter(any())).willReturn(Mono.empty());
		WebFilterChain decorated = decorator.decorate(chain, List.of(filter));
		decorated.filter(MockServerWebExchange.from(MockServerHttpRequest.get("/").build())).block();

		ArgumentCaptor<Observation.Context> context = ArgumentCaptor.forClass(Observation.Context.class);
		verify(handler, times(3)).onStop(context.capture());

		assertThat(context.getValue().getLowCardinalityKeyValue("spring.security.reached.filter.name").getValue())
			.isEqualTo(expectedFilterNameTag);
	}

	static Stream<Arguments> decorateFiltersWhenCompletesThenHasSpringSecurityReachedFilterNameTagArguments() {
		WebFilter filterWithName = new BasicAuthenticationFilter();

		// Anonymous class leads to an empty filter-name
		WebFilter filterWithoutName = new WebFilter() {
			@Override
			public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
				return chain.filter(exchange);
			}
		};

		return Stream.of(Arguments.of(filterWithName, "BasicAuthenticationFilter"),
				Arguments.of(filterWithoutName, "none"));
	}

	static class BasicAuthenticationFilter implements WebFilter {

		@Override
		public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
			return chain.filter(exchange);
		}

	}

	static class ErroringFilter implements WebFilter {

		@Override
		public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
			return Mono.error(() -> new RuntimeException("ack"));
		}

	}

	static class TerminatingFilter implements WebFilter {

		@Override
		public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
			return Mono.empty();
		}

	}

	static class AccumulatingObservationHandler implements ObservationHandler<Observation.Context> {

		List<Event> contexts = new ArrayList<>();

		@Override
		public boolean supportsContext(Observation.Context context) {
			return true;
		}

		@Override
		public void onStart(Observation.Context context) {
			this.contexts.add(new Event("start", context));
		}

		@Override
		public void onError(Observation.Context context) {
			this.contexts.add(new Event("error", context));
		}

		@Override
		public void onEvent(Observation.Event event, Observation.Context context) {
			this.contexts.add(new Event("event", context));
		}

		@Override
		public void onScopeOpened(Observation.Context context) {
			this.contexts.add(new Event("opened", context));
		}

		@Override
		public void onScopeClosed(Observation.Context context) {
			this.contexts.add(new Event("closed", context));
		}

		@Override
		public void onScopeReset(Observation.Context context) {
			this.contexts.add(new Event("reset", context));
		}

		@Override
		public void onStop(Observation.Context context) {
			this.contexts.add(new Event("stop", context));
		}

		private void assertSpanStart(int index, String name, String parentName) {
			Event event = this.contexts.get(index);
			assertThat(event.event).isEqualTo("start");
			if (event.contextualName == null) {
				assertThat(event.name).isEqualTo(name);
			}
			else {
				assertThat(event.contextualName).isEqualTo(name);
			}
			if (parentName == null) {
				return;
			}
			if (event.parentContextualName == null) {
				assertThat(event.parentName).isEqualTo(parentName);
			}
			else {
				assertThat(event.parentContextualName).isEqualTo(parentName);
			}
		}

		private void assertSpanStop(int index, String name) {
			Event event = this.contexts.get(index);
			assertThat(event.event).isEqualTo("stop");
			if (event.contextualName == null) {
				assertThat(event.name).isEqualTo(name);
			}
			else {
				assertThat(event.contextualName).isEqualTo(name);
			}
		}

		private void assertSpanError(int index) {
			Event event = this.contexts.get(index);
			assertThat(event.event).isEqualTo("error");
		}

		static class Event {

			String event;

			String name;

			String contextualName;

			String parentName;

			String parentContextualName;

			Event(String event, Observation.Context context) {
				this.event = event;
				this.name = context.getName();
				this.contextualName = context.getContextualName();
				if (context.getParentObservation() != null) {
					this.parentName = context.getParentObservation().getContextView().getName();
					this.parentContextualName = context.getParentObservation().getContextView().getContextualName();
				}
			}

		}

	}

}
