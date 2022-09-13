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

import io.micrometer.common.KeyValues;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationConvention;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.event.KeyValuesEvent;

/**
 * A strategy to collect {@link KeyValues} for
 * {@link org.springframework.security.authentication.event.AuthenticationSuccessEvent}s
 *
 * @author Josh Cummings
 * @since 6.0
 */
public final class AuthenticationSuccessObservationEventConverter
		implements Converter<AuthenticationSuccessEvent, Observation.Event> {

	private final ObservationConvention<AuthenticationObservationContext> convention = new AuthenticationObservationConvention();

	@Override
	public Observation.Event convert(AuthenticationSuccessEvent event) {
		AuthenticationObservationContext context = AuthenticationObservationContext.fromEvent(event);
		KeyValues kv = this.convention.getLowCardinalityKeyValues(context);
		return new KeyValuesEvent(kv, Observation.Event.of(context.getName()));
	}

}
