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

package org.springframework.security.core.context;

import java.util.function.Supplier;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.security.authentication.TestingAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link ObservationSecurityContextChangedListener}
 */
public class ObservationSecurityContextChangedListenerTests {

	private SecurityContext one = new SecurityContextImpl(new TestingAuthenticationToken("user", "pass"));

	private SecurityContext two = new SecurityContextImpl(new TestingAuthenticationToken("admin", "pass"));

	private ObservationRegistry observationRegistry;

	private ObservationSecurityContextChangedListener tested;

	@BeforeEach
	void setup() {
		this.observationRegistry = mock(ObservationRegistry.class);
		this.tested = new ObservationSecurityContextChangedListener(this.observationRegistry);
	}

	@Test
	void securityContextChangedWhenNoObservationThenNoEvents() {
		given(this.observationRegistry.getCurrentObservation()).willReturn(null);
		this.tested.securityContextChanged(new SecurityContextChangedEvent(this.one, this.two));
	}

	@Test
	void securityContextChangedWhenClearedEventThenAddsClearEventToObservation() {
		Observation observation = mock(Observation.class);
		given(this.observationRegistry.getCurrentObservation()).willReturn(observation);
		Supplier<SecurityContext> one = mock(Supplier.class);
		this.tested
				.securityContextChanged(new SecurityContextChangedEvent(one, SecurityContextChangedEvent.NO_CONTEXT));
		ArgumentCaptor<Observation.Event> event = ArgumentCaptor.forClass(Observation.Event.class);
		verify(observation).event(event.capture());
		assertThat(event.getValue().getName())
				.isEqualTo(ObservationSecurityContextChangedListener.SECURITY_CONTEXT_CLEARED);
		verifyNoInteractions(one);
	}

	@Test
	void securityContextChangedWhenNoChangeThenNoEventAddedToObservation() {
		Observation observation = mock(Observation.class);
		given(this.observationRegistry.getCurrentObservation()).willReturn(observation);
		this.tested.securityContextChanged(new SecurityContextChangedEvent(this.one, this.one));
		verifyNoInteractions(observation);
	}

	@Test
	void securityContextChangedWhenChangedEventThenAddsChangeEventToObservation() {
		Observation observation = mock(Observation.class);
		given(this.observationRegistry.getCurrentObservation()).willReturn(observation);
		this.tested.securityContextChanged(new SecurityContextChangedEvent(this.one, this.two));
		ArgumentCaptor<Observation.Event> event = ArgumentCaptor.forClass(Observation.Event.class);
		verify(observation).event(event.capture());
		assertThat(event.getValue().getName())
				.isEqualTo(ObservationSecurityContextChangedListener.SECURITY_CONTEXT_CHANGED);
	}

	@Test
	void securityContextChangedWhenCreatedEventThenAddsCreatedEventToObservation() {
		Observation observation = mock(Observation.class);
		given(this.observationRegistry.getCurrentObservation()).willReturn(observation);
		this.tested.securityContextChanged(new SecurityContextChangedEvent(null, this.one));
		ArgumentCaptor<Observation.Event> event = ArgumentCaptor.forClass(Observation.Event.class);
		verify(observation).event(event.capture());
		assertThat(event.getValue().getName())
				.isEqualTo(ObservationSecurityContextChangedListener.SECURITY_CONTEXT_CREATED);
	}

}
