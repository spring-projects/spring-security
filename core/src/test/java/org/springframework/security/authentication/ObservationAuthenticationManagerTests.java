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

package org.springframework.security.authentication;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import io.micrometer.observation.ObservationRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link ObservationAuthenticationManager}
 */
public class ObservationAuthenticationManagerTests {

	private ObservationRegistry registry;

	private ObservationHandler<Observation.Context> handler;

	private AuthenticationManager authenticationManager;

	private ObservationAuthenticationManager tested;

	private final Authentication token = new TestingAuthenticationToken("user", "pass");

	private final Authentication authentication = new TestingAuthenticationToken("user", "pass", "app");

	@BeforeEach
	void setup() {
		this.handler = mock(ObservationHandler.class);
		ObservationRegistry registry = ObservationRegistry.create();
		registry.observationConfig().observationHandler(this.handler);
		this.registry = registry;
		this.authenticationManager = mock(AuthenticationManager.class);
		this.tested = new ObservationAuthenticationManager(this.registry, this.authenticationManager);
	}

	@Test
	void authenticateWhenDefaultsThenObserves() {
		given(this.handler.supportsContext(any())).willReturn(true);
		given(this.authenticationManager.authenticate(any())).willReturn(this.authentication);
		this.tested.authenticate(this.token);
		ArgumentCaptor<Observation.Context> captor = ArgumentCaptor.forClass(Observation.Context.class);
		verify(this.handler).onStart(captor.capture());
		assertThat(captor.getValue().getName()).isEqualTo(AuthenticationObservationConvention.OBSERVATION_NAME);
		assertThat(captor.getValue().getError()).isNull();
		assertThat(captor.getValue()).isInstanceOf(AuthenticationObservationContext.class);
		AuthenticationObservationContext context = (AuthenticationObservationContext) captor.getValue();
		assertThat(context.getAuthenticationManagerClass()).isEqualTo(this.authenticationManager.getClass());
		assertThat(context.getAuthenticationRequest()).isEqualTo(this.token);
		assertThat(context.getAuthenticationResult()).isEqualTo(this.authentication);

	}

	@Test
	void authenticationWhenErrorsThenObserves() {
		given(this.handler.supportsContext(any())).willReturn(true);
		given(this.authenticationManager.authenticate(any())).willThrow(BadCredentialsException.class);
		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> this.tested.authenticate(this.token));
		ArgumentCaptor<Observation.Context> captor = ArgumentCaptor.forClass(Observation.Context.class);
		verify(this.handler).onStart(captor.capture());
		assertThat(captor.getValue().getName()).isEqualTo(AuthenticationObservationConvention.OBSERVATION_NAME);
		assertThat(captor.getValue().getError()).isInstanceOf(AuthenticationException.class);
		assertThat(captor.getValue()).isInstanceOf(AuthenticationObservationContext.class);
		AuthenticationObservationContext context = (AuthenticationObservationContext) captor.getValue();
		assertThat(context.getAuthenticationManagerClass()).isEqualTo(this.authenticationManager.getClass());
		assertThat(context.getAuthenticationRequest()).isEqualTo(this.token);
		assertThat(context.getAuthenticationResult()).isNull();
	}

}
