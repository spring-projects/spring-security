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

import io.micrometer.common.KeyValues;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;

import org.springframework.context.ApplicationListener;
import org.springframework.core.convert.converter.Converter;
import org.springframework.util.Assert;

/**
 * A listener for a single security event. Pipes the event to Micrometer's
 * {@link Observation} API
 *
 * @param <T> the type of {@link SecurityEvent}
 * @author Josh Cummings
 * @since 6.0
 */
public final class ObservationSecurityEventListener<T extends SecurityEvent> implements ApplicationListener<T> {

	private final ObservationRegistry registry;

	private final Converter<T, KeyValues> keyValuesConverter;

	/**
	 * Construct a {@link ObservationSecurityEventListener}
	 * @param registry the {@link ObservationRegistry} to use
	 * @param keyValuesConverter the strategy to deriving the event context
	 */
	public ObservationSecurityEventListener(ObservationRegistry registry, Converter<T, KeyValues> keyValuesConverter) {
		Assert.notNull(registry, "registry cannot be null");
		Assert.notNull(keyValuesConverter, "keyValuesConverter cannot be null");
		this.registry = registry;
		this.keyValuesConverter = keyValuesConverter;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void onApplicationEvent(T event) {
		Observation observation = this.registry.getCurrentObservation();
		if (observation != null) {
			String name = "spring.security." + event.getEventType();
			KeyValues kv = this.keyValuesConverter.convert(event);
			observation.event(new KeyValuesEvent(kv, Observation.Event.of(name)));
		}
	}

}
