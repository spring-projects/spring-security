/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.server.resource;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link BearerTokenAuthenticationException}.
 *
 * @author Vedran Pavic
 */
public class BearerTokenAuthenticationExceptionTests {

	private static final BearerTokenError TEST_ERROR = new BearerTokenError("test-code");

	private static final String TEST_MESSAGE = "test-message";

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Test
	public void constructorWithAllParametersWhenErrorIsValidThenCreated() {
		BearerTokenAuthenticationException exception = new BearerTokenAuthenticationException(TEST_ERROR, TEST_MESSAGE,
			new Throwable());

		assertThat(exception.getError()).isEqualTo(TEST_ERROR);
	}

	@Test
	public void constructorWithAllParametersWhenErrorIsNullThenThrowIllegalArgumentException() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("error must not be null");

		new BearerTokenAuthenticationException(null, TEST_MESSAGE, new Throwable());
	}

	@Test
	public void constructorWithErrorAndMessageWhenErrorIsValidThenCreated() {
		BearerTokenAuthenticationException exception = new BearerTokenAuthenticationException(TEST_ERROR, TEST_MESSAGE);

		assertThat(exception.getError()).isEqualTo(TEST_ERROR);
	}

	@Test
	public void constructorWithErrorAndMessageWhenErrorIsNullThenThrowIllegalArgumentException() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("error must not be null");

		new BearerTokenAuthenticationException(null, TEST_MESSAGE);
	}

}
