/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.web.server.authentication.session;

import java.util.Collections;

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.server.authentication.MaximumSessionsContext;
import org.springframework.security.web.server.authentication.PreventLoginServerMaximumSessionsExceededHandler;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link PreventLoginServerMaximumSessionsExceededHandler}.
 *
 * @author Marcus da Coregio
 */
class PreventLoginServerMaximumSessionsExceededHandlerTests {

	@Test
	void handleWhenInvokedThenThrowsSessionAuthenticationException() {
		PreventLoginServerMaximumSessionsExceededHandler handler = new PreventLoginServerMaximumSessionsExceededHandler();
		MaximumSessionsContext context = new MaximumSessionsContext(TestAuthentication.authenticatedUser(),
				Collections.emptyList(), 1);
		assertThatExceptionOfType(SessionAuthenticationException.class)
			.isThrownBy(() -> handler.handle(context).block())
			.withMessage("Maximum sessions of 1 for authentication 'user' exceeded");
	}

}
