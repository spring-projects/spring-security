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

package org.springframework.security.web.server;

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import io.micrometer.observation.ObservationRegistry;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.web.server.ObservationWebFilterChainDecorator.WebFilterChainObservationContext;
import org.springframework.security.web.server.ObservationWebFilterChainDecorator.WebFilterChainObservationConvention;
import org.springframework.security.web.server.ObservationWebFilterChainDecorator.WebFilterObservation;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher.MatchResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class WebFilterChainProxyTests {

	// gh-4668
	@Test
	public void filterWhenNoMatchThenContinuesChainAnd404() {
		List<WebFilter> filters = Arrays.asList(new Http200WebFilter());
		ServerWebExchangeMatcher notMatch = (exchange) -> MatchResult.notMatch();
		MatcherSecurityWebFilterChain chain = new MatcherSecurityWebFilterChain(notMatch, filters);
		WebFilterChainProxy filter = new WebFilterChainProxy(chain);
		WebTestClient.bindToController(new Object()).webFilter(filter).build().get().exchange().expectStatus()
				.isNotFound();
	}

	@Test
	public void doFilterWhenMatchesThenObservationRegistryObserves() {
		ObservationHandler<Observation.Context> handler = mock(ObservationHandler.class);
		given(handler.supportsContext(any())).willReturn(true);
		ObservationRegistry registry = ObservationRegistry.create();
		registry.observationConfig().observationHandler(handler);
		List<WebFilter> filters = Arrays.asList(new PassthroughWebFilter());
		ServerWebExchangeMatcher match = (exchange) -> MatchResult.match();
		MatcherSecurityWebFilterChain chain = new MatcherSecurityWebFilterChain(match, filters);
		WebFilterChainProxy fcp = new WebFilterChainProxy(chain);
		fcp.setFilterChainDecorator(new ObservationWebFilterChainDecorator(registry));
		WebFilter filter = WebFilterObservation.create(Observation.createNotStarted("wrap", registry)).wrap(fcp);
		WebFilterChain mockChain = mock(WebFilterChain.class);
		given(mockChain.filter(any())).willReturn(Mono.empty());
		filter.filter(MockServerWebExchange.from(MockServerHttpRequest.get("/")), mockChain).block();
		ArgumentCaptor<Observation.Context> captor = ArgumentCaptor.forClass(Observation.Context.class);
		verify(handler, times(4)).onStart(captor.capture());
		Iterator<Observation.Context> contexts = captor.getAllValues().iterator();
		assertThat(contexts.next().getName()).isEqualTo("wrap");
		assertFilterChainObservation(contexts.next(), "before", 1);
		assertThat(contexts.next().getName()).isEqualTo(ObservationWebFilterChainDecorator.SECURED_OBSERVATION_NAME);
		assertFilterChainObservation(contexts.next(), "after", 1);
	}

	@Test
	public void doFilterWhenMismatchesThenObservationRegistryObserves() {
		ObservationHandler<Observation.Context> handler = mock(ObservationHandler.class);
		given(handler.supportsContext(any())).willReturn(true);
		ObservationRegistry registry = ObservationRegistry.create();
		registry.observationConfig().observationHandler(handler);
		List<WebFilter> filters = Arrays.asList(new PassthroughWebFilter());
		ServerWebExchangeMatcher notMatch = (exchange) -> MatchResult.notMatch();
		MatcherSecurityWebFilterChain chain = new MatcherSecurityWebFilterChain(notMatch, filters);
		WebFilterChainProxy fcp = new WebFilterChainProxy(chain);
		fcp.setFilterChainDecorator(new ObservationWebFilterChainDecorator(registry));
		WebFilter filter = WebFilterObservation.create(Observation.createNotStarted("wrap", registry)).wrap(fcp);
		WebFilterChain mockChain = mock(WebFilterChain.class);
		given(mockChain.filter(any())).willReturn(Mono.empty());
		filter.filter(MockServerWebExchange.from(MockServerHttpRequest.get("/")), mockChain).block();
		ArgumentCaptor<Observation.Context> captor = ArgumentCaptor.forClass(Observation.Context.class);
		verify(handler, times(2)).onStart(captor.capture());
		Iterator<Observation.Context> contexts = captor.getAllValues().iterator();
		assertThat(contexts.next().getName()).isEqualTo("wrap");
		assertThat(contexts.next().getName()).isEqualTo(ObservationWebFilterChainDecorator.UNSECURED_OBSERVATION_NAME);
	}

	@Test
	public void doFilterWhenFilterExceptionThenObservationRegistryObserves() {
		ObservationHandler<Observation.Context> handler = mock(ObservationHandler.class);
		given(handler.supportsContext(any())).willReturn(true);
		ObservationRegistry registry = ObservationRegistry.create();
		registry.observationConfig().observationHandler(handler);
		WebFilter error = mock(WebFilter.class);
		given(error.filter(any(), any())).willReturn(Mono.error(new IllegalStateException()));
		List<WebFilter> filters = Arrays.asList(error);
		ServerWebExchangeMatcher match = (exchange) -> MatchResult.match();
		MatcherSecurityWebFilterChain chain = new MatcherSecurityWebFilterChain(match, filters);
		WebFilterChainProxy fcp = new WebFilterChainProxy(chain);
		fcp.setFilterChainDecorator(new ObservationWebFilterChainDecorator(registry));
		WebFilter filter = WebFilterObservation.create(Observation.createNotStarted("wrap", registry)).wrap(fcp);
		WebFilterChain mockChain = mock(WebFilterChain.class);
		given(mockChain.filter(any())).willReturn(Mono.empty());
		assertThatExceptionOfType(IllegalStateException.class).isThrownBy(
				() -> filter.filter(MockServerWebExchange.from(MockServerHttpRequest.get("/")), mockChain).block());
		ArgumentCaptor<Observation.Context> captor = ArgumentCaptor.forClass(Observation.Context.class);
		verify(handler, times(2)).onStart(captor.capture());
		verify(handler, atLeastOnce()).onError(any());
		Iterator<Observation.Context> contexts = captor.getAllValues().iterator();
		assertThat(contexts.next().getName()).isEqualTo("wrap");
		assertFilterChainObservation(contexts.next(), "before", 1);
	}

	static void assertFilterChainObservation(Observation.Context context, String filterSection, int chainPosition) {
		assertThat(context).isInstanceOf(WebFilterChainObservationContext.class);
		WebFilterChainObservationContext filterChainObservationContext = (WebFilterChainObservationContext) context;
		assertThat(context.getName()).isEqualTo(WebFilterChainObservationConvention.CHAIN_OBSERVATION_NAME);
		assertThat(context.getContextualName()).endsWith(filterSection);
		assertThat(filterChainObservationContext.getChainPosition()).isEqualTo(chainPosition);
	}

	static class Http200WebFilter implements WebFilter {

		@Override
		public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
			return Mono.fromRunnable(() -> exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN));
		}

	}

	static class PassthroughWebFilter implements WebFilter {

		@Override
		public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
			return chain.filter(exchange);
		}

	}

}
