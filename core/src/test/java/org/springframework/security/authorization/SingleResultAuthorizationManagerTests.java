/*
 * Copyright 2002-2025 the original author or authors.
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

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link SingleResultAuthorizationManager}.
 *
 * @author Max Batischev
 */
public class SingleResultAuthorizationManagerTests {

	private SingleResultAuthorizationManager<?> manager;

	@Test
	void authorizeWhenManagerWithGrantedAuthorizationResultIsCreatedThenAuthorizes() {
		this.manager = new SingleResultAuthorizationManager<>(new AuthorizationDecision(true));

		AuthorizationResult result = this.manager.authorize(null, null);

		assertThat(result.isGranted()).isTrue();
	}

	@Test
	void checkWhenManagerWithGrantedDecisionIsCreatedThenAuthorizes() {
		this.manager = new SingleResultAuthorizationManager<>(new AuthorizationDecision(true));

		AuthorizationResult result = this.manager.check(null, null);

		assertThat(result.isGranted()).isTrue();
	}

	@Test
	void checkWhenManagerWithGrantedCustomAuthorizationResultIsCreatedThenFails() {
		this.manager = new SingleResultAuthorizationManager<>((AuthorizationResult) () -> true);

		assertThatIllegalArgumentException().isThrownBy(() -> this.manager.check(null, null));
	}

	@Test
	void authorizeWhenPermitManagerUsesThenAuthorize() {
		AuthorizationResult result = SingleResultAuthorizationManager.permitAll().authorize(null, null);

		assertThat(result.isGranted()).isTrue();
	}

	@Test
	void authorizeWhenDenyManagerUsesThenDeny() {
		AuthorizationResult result = SingleResultAuthorizationManager.denyAll().authorize(null, null);

		assertThat(result.isGranted()).isFalse();
	}

	@Test
	void constructWhenNullResultIsPresentThenFails() {
		assertThatIllegalArgumentException().isThrownBy(() -> new SingleResultAuthorizationManager<>(null));
	}

}
