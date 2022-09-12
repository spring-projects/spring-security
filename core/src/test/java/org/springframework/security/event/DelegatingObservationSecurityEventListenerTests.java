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

package org.springframework.security.event;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import io.micrometer.observation.ObservationRegistry;
import io.micrometer.observation.ObservationTextPublisher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

public class DelegatingObservationSecurityEventListenerTests {

	private ObservationRegistry registry;

	@BeforeEach
	void setup() {
		this.registry = ObservationRegistry.create();
	}

	@Test
	void onApplicationEventWhenCustomKeyValuesConverterThenUses() {
		ObservationSecurityEventListener<AuthenticationSuccessEvent> observationListener = mock(
				ObservationSecurityEventListener.class);
		ApplicationListener<SecurityEvent> listener = DelegatingObservationSecurityEventListener
				.withDefaults(this.registry).add(AuthenticationSuccessEvent.class, observationListener).build();
		this.registry.observationConfig().observationHandler(new ObservationTextPublisher());
		Observation.createNotStarted("my.observation", this.registry).observe(() -> listener.onApplicationEvent(
				new AuthenticationSuccessEvent(new TestingAuthenticationToken("user", "password"))));
		verify(observationListener).onApplicationEvent(any(AuthenticationSuccessEvent.class));
	}

	@Test
	void onApplicationEventWhenCustomEventThenPublishes() {
		ApplicationListener<SecurityEvent> listener = DelegatingObservationSecurityEventListener
				.withDefaults(this.registry).build();
		ObservationHandler<?> handler = spy(new ObservationTextPublisher());
		this.registry.observationConfig().observationHandler(handler);
		Observation.createNotStarted("my.observation", this.registry).observe(() -> {
			listener.onApplicationEvent(new MyEvent(new Object()));
			listener.onApplicationEvent(
					new AuthenticationSuccessEvent(new TestingAuthenticationToken("user", "password")));
		});
		verify(handler, times(2)).onEvent(any(KeyValuesEvent.class), any());
	}

	private static class MyEvent extends SecurityEvent {

		MyEvent(Object source) {
			super(source);
		}

	}

}
