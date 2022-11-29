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

import io.micrometer.observation.ObservationHandler;
import io.micrometer.observation.ObservationRegistry;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
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

}
