/*
 * Copyright 2002-2020 the original author or authors.
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

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link AuthorizationManager}.
 *
 * @author Evgeniy Cheban
 */
public class AuthorizationManagerTests {

	@Test
	public void verifyWhenCheckReturnedGrantedDecisionThenPasses() {
		AuthorizationManager<Object> manager = (a, o) -> new AuthorizationDecision(true);

		Authentication authentication = new TestingAuthenticationToken("user", "password", "ROLE_1", "ROLE_2");
		Object object = new Object();

		manager.verify(() -> authentication, object);
	}

	@Test
	public void verifyWhenCheckReturnedNullThenPasses() {
		AuthorizationManager<Object> manager = (a, o) -> null;

		Authentication authentication = new TestingAuthenticationToken("user", "password", "ROLE_1", "ROLE_2");
		Object object = new Object();

		manager.verify(() -> authentication, object);
	}

	@Test
	public void verifyWhenCheckReturnedDeniedDecisionThenAccessDeniedException() {
		AuthorizationManager<Object> manager = (a, o) -> new AuthorizationDecision(false);

		Authentication authentication = new TestingAuthenticationToken("user", "password", "ROLE_1", "ROLE_2");
		Object object = new Object();

		assertThatExceptionOfType(AccessDeniedException.class)
				.isThrownBy(() -> manager.verify(() -> authentication, object)).withMessage("Access Denied");
	}

}
