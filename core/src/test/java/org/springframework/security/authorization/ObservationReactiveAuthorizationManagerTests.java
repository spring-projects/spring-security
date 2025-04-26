/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.authorization;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import io.micrometer.observation.ObservationRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link ObservationAuthorizationManager}
 */
public class ObservationReactiveAuthorizationManagerTests {

	private ObservationRegistry registry;

	private ObservationHandler<Observation.Context> handler;

	private ReactiveAuthorizationManager<Object> authorizationManager;

	private ObservationReactiveAuthorizationManager<Object> tested;

	private final Mono<Authentication> token = Mono.just(new TestingAuthenticationToken("user", "pass"));

	private final Object object = new Object();

	private final AuthorizationDecision grant = new AuthorizationDecision(true);

	private final AuthorizationDecision deny = new AuthorizationDecision(false);

	@BeforeEach
	void setup() {
		this.handler = mock(ObservationHandler.class);
		ObservationRegistry registry = ObservationRegistry.create();
		registry.observationConfig().observationHandler(this.handler);
		this.registry = registry;
		this.authorizationManager = mock(ReactiveAuthorizationManager.class);
		this.tested = new ObservationReactiveAuthorizationManager<>(this.registry, this.authorizationManager);
	}

	@Test
	void verifyWhenDefaultsThenObserves() {
		given(this.handler.supportsContext(any())).willReturn(true);
		given(this.authorizationManager.check(any(), any())).willReturn(Mono.just(this.grant));
		given(this.authorizationManager.authorize(any(), any())).willCallRealMethod();
		this.tested.verify(this.token, this.object).block();
		ArgumentCaptor<Observation.Context> captor = ArgumentCaptor.forClass(Observation.Context.class);
		verify(this.handler).onStart(captor.capture());
		assertThat(captor.getValue().getName()).isEqualTo(AuthorizationObservationConvention.OBSERVATION_NAME);
		assertThat(captor.getValue().getError()).isNull();
		assertThat(captor.getValue()).isInstanceOf(AuthorizationObservationContext.class);
		AuthorizationObservationContext<?> context = (AuthorizationObservationContext<?>) captor.getValue();
		assertThat(context.getAuthentication()).isNull();
		assertThat(context.getObject()).isEqualTo(this.object);
		assertThat(context.getDecision()).isEqualTo(this.grant);
	}

	@Test
	void verifyWhenErrorsThenObserves() {
		given(this.handler.supportsContext(any())).willReturn(true);
		given(this.authorizationManager.check(any(), any())).willReturn(Mono.just(this.deny));
		given(this.authorizationManager.authorize(any(), any())).willCallRealMethod();
		assertThatExceptionOfType(AccessDeniedException.class)
			.isThrownBy(() -> this.tested.verify(this.token, this.object).block());
		ArgumentCaptor<Observation.Context> captor = ArgumentCaptor.forClass(Observation.Context.class);
		verify(this.handler).onStart(captor.capture());
		assertThat(captor.getValue().getName()).isEqualTo(AuthorizationObservationConvention.OBSERVATION_NAME);
		assertThat(captor.getValue().getError()).isInstanceOf(AccessDeniedException.class);
		assertThat(captor.getValue()).isInstanceOf(AuthorizationObservationContext.class);
		AuthorizationObservationContext<?> context = (AuthorizationObservationContext<?>) captor.getValue();
		assertThat(context.getAuthentication()).isNull();
		assertThat(context.getObject()).isEqualTo(this.object);
		assertThat(context.getDecision()).isEqualTo(this.deny);
	}

	@Test
	void verifyWhenLooksUpAuthenticationThenObserves() {
		given(this.handler.supportsContext(any())).willReturn(true);
		given(this.authorizationManager.check(any(), any())).willAnswer((invocation) -> {
			((Mono<Authentication>) invocation.getArgument(0)).block();
			return Mono.just(this.grant);
		});
		given(this.authorizationManager.authorize(any(), any())).willCallRealMethod();
		this.tested.verify(this.token, this.object).block();
		ArgumentCaptor<Observation.Context> captor = ArgumentCaptor.forClass(Observation.Context.class);
		verify(this.handler).onStart(captor.capture());
		assertThat(captor.getValue().getName()).isEqualTo(AuthorizationObservationConvention.OBSERVATION_NAME);
		assertThat(captor.getValue().getError()).isNull();
		AuthorizationObservationContext<?> context = (AuthorizationObservationContext<?>) captor.getValue();
		assertThat(context.getAuthentication()).isEqualTo(this.token.block());
		assertThat(context.getObject()).isEqualTo(this.object);
		assertThat(context.getDecision()).isEqualTo(this.grant);
	}

	@Test
	void setObservationConventionWhenNullThenException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.tested.setObservationConvention(null));
	}

}
