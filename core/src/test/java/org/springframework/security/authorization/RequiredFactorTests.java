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
 * Tests for {@link RequiredFactor}.
 *
 * @author Rob Winch
 * @since 7.0
 */
class RequiredFactorTests {

	@Test
	void builderWhenNullAuthorityIllegalArgumentException() {
		RequiredFactor.Builder builder = RequiredFactor.builder();
		assertThatIllegalArgumentException().isThrownBy(() -> builder.build());
	}

	@Test
	void withAuthorityThenEquals() {
		RequiredFactor requiredPassword = RequiredFactor.withAuthority(GrantedAuthorities.FACTOR_PASSWORD_AUTHORITY)
			.build();
		assertThat(requiredPassword.getAuthority()).isEqualTo(GrantedAuthorities.FACTOR_PASSWORD_AUTHORITY);
		assertThat(requiredPassword.getValidDuration()).isNull();
	}

	@Test
	void builderValidDurationThenEquals() {
		Duration validDuration = Duration.ofMinutes(1);
		RequiredFactor requiredPassword = RequiredFactor.withAuthority(GrantedAuthorities.FACTOR_PASSWORD_AUTHORITY)
			.validDuration(validDuration)
			.build();
		assertThat(requiredPassword.getAuthority()).isEqualTo(GrantedAuthorities.FACTOR_PASSWORD_AUTHORITY);
		assertThat(requiredPassword.getValidDuration()).isEqualTo(validDuration);
	}

}
