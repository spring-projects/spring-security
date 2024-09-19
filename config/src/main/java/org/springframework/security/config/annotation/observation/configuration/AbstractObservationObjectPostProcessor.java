/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.config.annotation.observation.configuration;

import java.util.function.BiFunction;
import java.util.function.Function;

import io.micrometer.observation.ObservationRegistry;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;

abstract class AbstractObservationObjectPostProcessor<O> implements ObjectPostProcessor<O> {

	private final ObjectProvider<ObservationRegistry> observationRegistry;

	private final BiFunction<ObservationRegistry, O, O> wrapper;

	AbstractObservationObjectPostProcessor(ObjectProvider<ObservationRegistry> observationRegistry,
			Function<ObservationRegistry, O> constructor) {
		this(observationRegistry, (registry, object) -> constructor.apply(registry));
	}

	AbstractObservationObjectPostProcessor(ObjectProvider<ObservationRegistry> observationRegistry,
			BiFunction<ObservationRegistry, O, O> constructor) {
		this.observationRegistry = observationRegistry;
		this.wrapper = constructor;
	}

	@Override
	public <O1 extends O> O1 postProcess(O1 object) {
		ObservationRegistry registry = this.observationRegistry.getIfUnique(() -> ObservationRegistry.NOOP);
		if (registry.isNoop()) {
			return object;
		}
		return (O1) this.wrapper.apply(registry, object);
	}

}
