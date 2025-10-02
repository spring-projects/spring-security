/*
 * Copyright 2004-present the original author or authors.
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

import java.time.Duration;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.GrantedAuthorities;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link RequiredFactorError}.
 *
 * @author Rob Winch
 * @since 7.0
 */
class RequiredFactorErrorTests {

	public static final RequiredFactor REQUIRED_FACTOR = RequiredFactor
		.withAuthority(GrantedAuthorities.FACTOR_PASSWORD_AUTHORITY)
		.validDuration(Duration.ofHours(1))
		.build();

	@Test
	void createMissing() {
		RequiredFactorError error = RequiredFactorError.createMissing(REQUIRED_FACTOR);
		assertThat(error.isMissing()).isTrue();
		assertThat(error.isExpired()).isFalse();
		assertThat(error.getRequiredFactor()).isEqualTo(REQUIRED_FACTOR);
	}

	@Test
	void createExpired() {
		RequiredFactorError error = RequiredFactorError.createExpired(REQUIRED_FACTOR);
		assertThat(error.isMissing()).isFalse();
		assertThat(error.isExpired()).isTrue();
		assertThat(error.getRequiredFactor()).isEqualTo(REQUIRED_FACTOR);
	}

	@Test
	void createExpiredWhenNullValidDurationThenIllegalArgumentException() {
		RequiredFactor requiredPassword = RequiredFactor.withAuthority(GrantedAuthorities.FACTOR_PASSWORD_AUTHORITY)
			.build();
		assertThatIllegalArgumentException().isThrownBy(() -> RequiredFactorError.createExpired(requiredPassword));
	}

}
