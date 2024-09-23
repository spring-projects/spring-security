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

package org.springframework.security.config.observation;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link SecurityObservationSettings}
 */
public class SecurityObservationSettingsTests {

	@Test
	void withDefaultsThenFilterOffAuthenticationOnAuthorizationOn() {
		SecurityObservationSettings defaults = SecurityObservationSettings.withDefaults().build();
		assertThat(defaults.shouldObserveRequests()).isFalse();
		assertThat(defaults.shouldObserveAuthentications()).isTrue();
		assertThat(defaults.shouldObserveAuthorizations()).isTrue();
	}

	@Test
	void noObservationsWhenConstructedThenAllOff() {
		SecurityObservationSettings defaults = SecurityObservationSettings.noObservations();
		assertThat(defaults.shouldObserveRequests()).isFalse();
		assertThat(defaults.shouldObserveAuthentications()).isFalse();
		assertThat(defaults.shouldObserveAuthorizations()).isFalse();
	}

	@Test
	void withDefaultsWhenExclusionsThenInstanceReflects() {
		SecurityObservationSettings defaults = SecurityObservationSettings.withDefaults()
			.shouldObserveAuthentications(false)
			.shouldObserveAuthorizations(false)
			.shouldObserveRequests(true)
			.build();
		assertThat(defaults.shouldObserveRequests()).isTrue();
		assertThat(defaults.shouldObserveAuthentications()).isFalse();
		assertThat(defaults.shouldObserveAuthorizations()).isFalse();
	}

}
