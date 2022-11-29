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

package org.springframework.security.web;

import io.micrometer.observation.ObservationHandler;
import io.micrometer.observation.ObservationRegistry;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
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

}
