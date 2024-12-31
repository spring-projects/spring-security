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

package org.springframework.security.web.authentication.session;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * @author Claudenir Freitas
 * @since 6.5
 */
class SessionLimitTests {

	private final Authentication authentication = Mockito.mock(Authentication.class);

	@Test
	void testUnlimitedInstance() {
		SessionLimit sessionLimit = SessionLimit.UNLIMITED;
		int result = sessionLimit.apply(this.authentication);
		assertThat(result).isEqualTo(-1);
	}

	@ParameterizedTest
	@ValueSource(ints = { -1, 1, 2, 3 })
	void testInstanceWithValidMaxSessions(int maxSessions) {
		SessionLimit sessionLimit = SessionLimit.of(maxSessions);
		int result = sessionLimit.apply(this.authentication);
		assertThat(result).isEqualTo(maxSessions);
	}

	@Test
	void testInstanceWithInvalidMaxSessions() {
		assertThatIllegalArgumentException().isThrownBy(() -> SessionLimit.of(0))
			.withMessage(
					"MaximumLogins must be either -1 to allow unlimited logins, or a positive integer to specify a maximum");
	}

}
