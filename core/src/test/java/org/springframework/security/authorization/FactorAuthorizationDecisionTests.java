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

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.authority.FactorGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link FactorAuthorizationDecision}.
 *
 * @author Rob Winch
 * @since 7.0
 */
class FactorAuthorizationDecisionTests {

	@Test
	void isGrantedWhenEmptyThenTrue() {
		FactorAuthorizationDecision decision = new FactorAuthorizationDecision(List.of());
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	void isGrantedWhenNotEmptyThenFalse() {
		RequiredFactor requiredPassword = RequiredFactor.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
			.build();
		RequiredFactorError missingPassword = RequiredFactorError.createMissing(requiredPassword);
		FactorAuthorizationDecision decision = new FactorAuthorizationDecision(List.of(missingPassword));
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	void getFactorErrors() {
		RequiredFactor requiredPassword = RequiredFactor.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
			.build();
		RequiredFactorError missingPassword = RequiredFactorError.createMissing(requiredPassword);
		List<RequiredFactorError> factorErrors = List.of(missingPassword);
		FactorAuthorizationDecision decision = new FactorAuthorizationDecision(factorErrors);
		assertThat(decision.getFactorErrors()).isEqualTo(factorErrors);
	}

	@Test
	void constructorWhenNullThenThrowIllegalArgumentException() {
		List<RequiredFactorError> factorErrors = null;
		assertThatIllegalArgumentException().isThrownBy(() -> new FactorAuthorizationDecision(factorErrors));
	}

	@Test
	void constructorWhenContainsNullThenThrowIllegalArgumentException() {
		RequiredFactor requiredPassword = RequiredFactor.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
			.build();
		RequiredFactorError missingPassword = RequiredFactorError.createMissing(requiredPassword);
		List<RequiredFactorError> hasNullValue = Arrays.asList(missingPassword, null);
		assertThatIllegalArgumentException().isThrownBy(() -> new FactorAuthorizationDecision(hasNullValue));
	}

}
