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

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

/**
 * Tests for {@link ConditionalAuthorizationManager}.
 *
 * @author Rob Winch
 */
public class ConditionalAuthorizationManagerTests {

	@Test
	void authorizeWhenAuthenticationIsNullThenUsesWhenFalse() {
		ConditionalAuthorizationManager<Object> manager = ConditionalAuthorizationManager.when((auth) -> true)
			.whenTrue(SingleResultAuthorizationManager.denyAll())
			.whenFalse(SingleResultAuthorizationManager.permitAll())
			.build();

		AuthorizationResult result = manager.authorize(() -> null, new Object());

		assertThat(result).isNotNull();
		assertThat(result.isGranted()).isTrue();
	}

	@Test
	void authorizeWhenConditionIsTrueThenUsesWhenTrue() {
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		ConditionalAuthorizationManager<Object> manager = ConditionalAuthorizationManager.when((auth) -> true)
			.whenTrue(SingleResultAuthorizationManager.permitAll())
			.whenFalse(SingleResultAuthorizationManager.denyAll())
			.build();

		AuthorizationResult result = manager.authorize(() -> authentication, new Object());

		assertThat(result).isNotNull();
		assertThat(result.isGranted()).isTrue();
	}

	@Test
	void authorizeWhenConditionIsFalseThenUsesWhenFalse() {
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		ConditionalAuthorizationManager<Object> manager = ConditionalAuthorizationManager.when((auth) -> false)
			.whenTrue(SingleResultAuthorizationManager.permitAll())
			.whenFalse(SingleResultAuthorizationManager.denyAll())
			.build();

		AuthorizationResult result = manager.authorize(() -> authentication, new Object());

		assertThat(result).isNotNull();
		assertThat(result.isGranted()).isFalse();
	}

	@Test
	void authorizeWhenConditionDependsOnAuthenticationThenEvaluatesCorrectly() {
		Authentication admin = new TestingAuthenticationToken("admin", "password", "ROLE_ADMIN");
		Authentication user = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		ConditionalAuthorizationManager<Object> manager = ConditionalAuthorizationManager
			.when((auth) -> auth.getAuthorities().stream().anyMatch((a) -> "ROLE_ADMIN".equals(a.getAuthority())))
			.whenTrue(SingleResultAuthorizationManager.permitAll())
			.whenFalse(SingleResultAuthorizationManager.denyAll())
			.build();

		assertThat(manager.authorize(() -> admin, new Object()).isGranted()).isTrue();
		assertThat(manager.authorize(() -> user, new Object()).isGranted()).isFalse();
	}

	@Test
	void buildWhenWhenFalseNotSetThenDefaultsToPermitAll() {
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		ConditionalAuthorizationManager<Object> manager = ConditionalAuthorizationManager.when((auth) -> false)
			.whenTrue(SingleResultAuthorizationManager.denyAll())
			.build();

		AuthorizationResult result = manager.authorize(() -> authentication, new Object());

		assertThat(result).isNotNull();
		assertThat(result.isGranted()).isTrue();
	}

	@Test
	void whenWhenConditionIsNullThenThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> ConditionalAuthorizationManager.when(null))
			.withMessage("condition cannot be null");
	}

	@Test
	void buildWhenWhenTrueNotSetThenThrowsException() {
		assertThatIllegalStateException().isThrownBy(() -> ConditionalAuthorizationManager.when((auth) -> true).build())
			.withMessage("whenTrue is required");
	}

	@Test
	void builderWhenWhenTrueIsNullThenThrowsException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> ConditionalAuthorizationManager.when((auth) -> true).whenTrue(null))
			.withMessage("whenTrue cannot be null");
	}

	@Test
	void builderWhenWhenFalseIsNullThenThrowsException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> ConditionalAuthorizationManager.when((auth) -> true)
				.whenTrue(SingleResultAuthorizationManager.permitAll())
				.whenFalse(null))
			.withMessage("whenFalse cannot be null");
	}

}
