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

package org.springframework.security.authorization.method;

import org.junit.jupiter.api.Test;

import org.springframework.security.authorization.AuthorizationDeniedException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link NullReturningMethodAuthorizationDeniedHandler}.
 *
 * @author Heejong Yoon
 */
class NullReturningMethodAuthorizationDeniedHandlerTests {

	@Test
	void handleNullReturningMethod() {
		assertThat(new NullReturningMethodAuthorizationDeniedHandler().handleDeniedInvocation(null, null)).isNull();
	}

	@Test
	void handleNullReturningMethodWithException() {
		assertThatExceptionOfType(AuthorizationDeniedException.class)
			.isThrownBy(() -> new NullReturningMethodAuthorizationDeniedHandler().handleDeniedInvocation(null,
					new AuthorizationDeniedException("test")));
	}

	@Test
	void handleNullReturningMethodWithInvocationResult() {
		assertThat(new NullReturningMethodAuthorizationDeniedHandler().handleDeniedInvocationResult(null, null))
			.isNull();
	}

	@Test
	void handleNullReturningMethodWithInvocationResultWithException() {
		assertThatExceptionOfType(AuthorizationDeniedException.class)
			.isThrownBy(() -> new NullReturningMethodAuthorizationDeniedHandler().handleDeniedInvocationResult(null,
					new AuthorizationDeniedException("test")));
	}

}
