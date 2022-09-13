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

/**
 * An {@link Observation.Event} that holds associated {@link KeyValues}
 *
 * @author Josh Cummings
 * @since 6.0
 */
public class KeyValuesObservationEvent implements Observation.Event {

	private final Observation.Event event;

	private final KeyValues kv;

	public KeyValuesObservationEvent(KeyValues kv, Observation.Event event) {
		this.event = event;
		this.kv = (kv != null) ? kv : KeyValues.empty();
	}

	@Override
	public String getName() {
		return this.event.getName();
	}

	@Override
	public String getContextualName() {
		return this.event.getContextualName();
	}

	@Override
	public KeyValuesObservationEvent format(Object... dynamicEntriesForContextualName) {
		return new KeyValuesObservationEvent(this.kv, this.event.format(dynamicEntriesForContextualName));
	}

	public KeyValues getKeyValues() {
		return this.kv;
	}

	public String toString() {
		String prefix = super.toString();
		if (KeyValues.empty().equals(this.kv)) {
			return prefix;
		}
		return prefix + ", event.values=" + this.kv;
	}

}
