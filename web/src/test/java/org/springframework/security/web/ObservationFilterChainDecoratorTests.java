/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.web;

import java.io.IOException;
import java.util.List;
import java.util.stream.Stream;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import io.micrometer.observation.ObservationRegistry;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link ObservationFilterChainDecorator}
 */
public class ObservationFilterChainDecoratorTests {

	@Test
	void decorateWhenDefaultsThenObserves() throws Exception {
		ObservationHandler<?> handler = mock(ObservationHandler.class);
		given(handler.supportsContext(any())).willReturn(true);
		ObservationRegistry registry = ObservationRegistry.create();
		registry.observationConfig().observationHandler(handler);
		ObservationFilterChainDecorator decorator = new ObservationFilterChainDecorator(registry);
		FilterChain chain = mock(FilterChain.class);
		FilterChain decorated = decorator.decorate(chain);
		decorated.doFilter(new MockHttpServletRequest("GET", "/"), new MockHttpServletResponse());
		verify(handler).onStart(any());
	}

	@Test
	void decorateWhenNoopThenDoesNotObserve() throws Exception {
		ObservationHandler<?> handler = mock(ObservationHandler.class);
		given(handler.supportsContext(any())).willReturn(true);
		ObservationRegistry registry = ObservationRegistry.NOOP;
		registry.observationConfig().observationHandler(handler);
		ObservationFilterChainDecorator decorator = new ObservationFilterChainDecorator(registry);
		FilterChain chain = mock(FilterChain.class);
		FilterChain decorated = decorator.decorate(chain);
		decorated.doFilter(new MockHttpServletRequest("GET", "/"), new MockHttpServletResponse());
		verifyNoInteractions(handler);
	}

	@Test
	void decorateFiltersWhenDefaultsThenObserves() throws Exception {
		ObservationHandler<?> handler = mock(ObservationHandler.class);
		given(handler.supportsContext(any())).willReturn(true);
		ObservationRegistry registry = ObservationRegistry.create();
		registry.observationConfig().observationHandler(handler);
		ObservationFilterChainDecorator decorator = new ObservationFilterChainDecorator(registry);
		FilterChain chain = mock(FilterChain.class);
		Filter filter = mock(Filter.class);
		FilterChain decorated = decorator.decorate(chain, List.of(filter));
		decorated.doFilter(new MockHttpServletRequest("GET", "/"), new MockHttpServletResponse());
		verify(handler, times(2)).onStart(any());
		ArgumentCaptor<Observation.Event> event = ArgumentCaptor.forClass(Observation.Event.class);
		verify(handler, times(2)).onEvent(event.capture(), any());
		List<Observation.Event> events = event.getAllValues();
		assertThat(events.get(0).getName()).isEqualTo(filter.getClass().getSimpleName() + ".before");
		assertThat(events.get(1).getName()).isEqualTo(filter.getClass().getSimpleName() + ".after");
	}

	@Test
	void decorateFiltersWhenDefaultsThenUsesEventName() throws Exception {
		ObservationHandler<?> handler = mock(ObservationHandler.class);
		given(handler.supportsContext(any())).willReturn(true);
		ObservationRegistry registry = ObservationRegistry.create();
		registry.observationConfig().observationHandler(handler);
		ObservationFilterChainDecorator decorator = new ObservationFilterChainDecorator(registry);
		FilterChain chain = mock(FilterChain.class);
		Filter filter = new BasicAuthenticationFilter();
		FilterChain decorated = decorator.decorate(chain, List.of(filter));
		decorated.doFilter(new MockHttpServletRequest("GET", "/"), new MockHttpServletResponse());
		ArgumentCaptor<Observation.Event> event = ArgumentCaptor.forClass(Observation.Event.class);
		verify(handler, times(2)).onEvent(event.capture(), any());
		List<Observation.Event> events = event.getAllValues();
		assertThat(events.get(0).getName()).isEqualTo("authentication.basic.before");
		assertThat(events.get(1).getName()).isEqualTo("authentication.basic.after");
	}

	// gh-12787
	@Test
	void decorateFiltersWhenErrorsThenClosesObservationOnlyOnce() throws Exception {
		ObservationHandler<?> handler = mock(ObservationHandler.class);
		given(handler.supportsContext(any())).willReturn(true);
		ObservationRegistry registry = ObservationRegistry.create();
		registry.observationConfig().observationHandler(handler);
		ObservationFilterChainDecorator decorator = new ObservationFilterChainDecorator(registry);
		FilterChain chain = mock(FilterChain.class);
		Filter filter = mock(Filter.class);
		willThrow(IllegalArgumentException.class).given(filter).doFilter(any(), any(), any());
		FilterChain decorated = decorator.decorate(chain, List.of(filter));
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(
				() -> decorated.doFilter(new MockHttpServletRequest("GET", "/"), new MockHttpServletResponse()));
		verify(handler).onScopeClosed(any());
	}

	@ParameterizedTest
	@MethodSource("decorateFiltersWhenCompletesThenHasSpringSecurityReachedFilterNameTag")
	void decorateFiltersWhenCompletesThenHasSpringSecurityReachedFilterNameTag(Filter filter,
			String expectedFilterNameTag) throws Exception {
		ObservationHandler<Observation.Context> handler = mock(ObservationHandler.class);
		given(handler.supportsContext(any())).willReturn(true);
		ObservationRegistry registry = ObservationRegistry.create();
		registry.observationConfig().observationHandler(handler);
		ObservationFilterChainDecorator decorator = new ObservationFilterChainDecorator(registry);
		FilterChain chain = mock(FilterChain.class);
		FilterChain decorated = decorator.decorate(chain, List.of(filter));
		decorated.doFilter(new MockHttpServletRequest("GET", "/"), new MockHttpServletResponse());
		ArgumentCaptor<Observation.Context> context = ArgumentCaptor.forClass(Observation.Context.class);
		verify(handler, times(3)).onScopeClosed(context.capture());
		assertThat(context.getValue().getLowCardinalityKeyValue("spring.security.reached.filter.name").getValue())
			.isEqualTo(expectedFilterNameTag);
	}

	// gh-13660
	@Test
	void observationNamesDoNotContainDashes() {
		ObservationFilterChainDecorator.ObservationFilter.OBSERVATION_NAMES.values()
			.forEach((name) -> assertThat(name).doesNotContain("-"));
	}

	static Stream<Arguments> decorateFiltersWhenCompletesThenHasSpringSecurityReachedFilterNameTag() {
		Filter filterWithName = new BasicAuthenticationFilter();

		// Anonymous class leads to an empty filter-name
		Filter filterWithoutName = new Filter() {
			@Override
			public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
					throws IOException, ServletException {
				chain.doFilter(request, response);
			}
		};

		return Stream.of(Arguments.of(filterWithName, "BasicAuthenticationFilter"),
				Arguments.of(filterWithoutName, "none"));
	}

	private static class BasicAuthenticationFilter implements Filter {

		@Override
		public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
				throws IOException, ServletException {
			chain.doFilter(request, response);
		}

	}

}
