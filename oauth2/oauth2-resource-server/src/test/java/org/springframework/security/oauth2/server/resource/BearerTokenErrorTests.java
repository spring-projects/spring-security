/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.oauth2.server.resource;

import org.junit.Test;

import org.springframework.http.HttpStatus;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Tests for {@link BearerTokenError}
 *
 * @author Vedran Pavic
 * @author Josh Cummings
 */
public class BearerTokenErrorTests {

	private static final String TEST_ERROR_CODE = "test-code";

	private static final HttpStatus TEST_HTTP_STATUS = HttpStatus.UNAUTHORIZED;

	private static final String TEST_DESCRIPTION = "test-description";

	private static final String TEST_URI = "https://example.com";

	private static final String TEST_SCOPE = "test-scope";

	@Test
	public void constructorWithErrorCodeWhenErrorCodeIsValidThenCreated() {
		BearerTokenError error = new BearerTokenError(TEST_ERROR_CODE, TEST_HTTP_STATUS, null, null);

		assertThat(error.getErrorCode()).isEqualTo(TEST_ERROR_CODE);
		assertThat(error.getHttpStatus()).isEqualTo(TEST_HTTP_STATUS);
		assertThat(error.getDescription()).isNull();
		assertThat(error.getUri()).isNull();
		assertThat(error.getScope()).isNull();
	}

	@Test
	public void constructorWithErrorCodeAndHttpStatusWhenErrorCodeIsNullThenThrowIllegalArgumentException() {
		assertThatCode(() -> new BearerTokenError(null, TEST_HTTP_STATUS, null, null))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("errorCode cannot be empty");
	}

	@Test
	public void constructorWithErrorCodeAndHttpStatusWhenErrorCodeIsEmptyThenThrowIllegalArgumentException() {
		assertThatCode(() -> new BearerTokenError("", TEST_HTTP_STATUS, null, null))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("errorCode cannot be empty");
	}

	@Test
	public void constructorWithErrorCodeAndHttpStatusWhenHttpStatusIsNullThenThrowIllegalArgumentException() {
		assertThatCode(() -> new BearerTokenError(TEST_ERROR_CODE, null, null, null))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("httpStatus cannot be null");
	}

	@Test
	public void constructorWithAllParametersWhenAllParametersAreValidThenCreated() {
		BearerTokenError error = new BearerTokenError(TEST_ERROR_CODE, TEST_HTTP_STATUS, TEST_DESCRIPTION, TEST_URI,
				TEST_SCOPE);

		assertThat(error.getErrorCode()).isEqualTo(TEST_ERROR_CODE);
		assertThat(error.getHttpStatus()).isEqualTo(TEST_HTTP_STATUS);
		assertThat(error.getDescription()).isEqualTo(TEST_DESCRIPTION);
		assertThat(error.getUri()).isEqualTo(TEST_URI);
		assertThat(error.getScope()).isEqualTo(TEST_SCOPE);
	}

	@Test
	public void constructorWithAllParametersWhenErrorCodeIsNullThenThrowIllegalArgumentException() {
		assertThatCode(() -> new BearerTokenError(null, TEST_HTTP_STATUS, TEST_DESCRIPTION, TEST_URI, TEST_SCOPE))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("errorCode cannot be empty");
	}

	@Test
	public void constructorWithAllParametersWhenErrorCodeIsEmptyThenThrowIllegalArgumentException() {
		assertThatCode(() -> new BearerTokenError("", TEST_HTTP_STATUS, TEST_DESCRIPTION, TEST_URI, TEST_SCOPE))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("errorCode cannot be empty");
	}

	@Test
	public void constructorWithAllParametersWhenHttpStatusIsNullThenThrowIllegalArgumentException() {
		assertThatCode(() -> new BearerTokenError(TEST_ERROR_CODE, null, TEST_DESCRIPTION, TEST_URI, TEST_SCOPE))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("httpStatus cannot be null");
	}

	@Test
	public void constructorWithAllParametersWhenErrorCodeIsInvalidThenThrowIllegalArgumentException() {
		assertThatCode(() -> new BearerTokenError(TEST_ERROR_CODE + "\"", TEST_HTTP_STATUS, TEST_DESCRIPTION,
				TEST_URI, TEST_SCOPE))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("errorCode")
				.hasMessageContaining("RFC 6750");
	}

	@Test
	public void constructorWithAllParametersWhenDescriptionIsInvalidThenThrowIllegalArgumentException() {
		assertThatCode(() -> new BearerTokenError(TEST_ERROR_CODE, TEST_HTTP_STATUS, TEST_DESCRIPTION + "\"",
				TEST_URI, TEST_SCOPE))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("description")
				.hasMessageContaining("RFC 6750");
	}

	@Test
	public void constructorWithAllParametersWhenErrorUriIsInvalidThenThrowIllegalArgumentException() {
		assertThatCode(() -> new BearerTokenError(TEST_ERROR_CODE, TEST_HTTP_STATUS, TEST_DESCRIPTION,
				TEST_URI + "\"", TEST_SCOPE))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("errorUri")
				.hasMessageContaining("RFC 6750");
	}

	@Test
	public void constructorWithAllParametersWhenScopeIsInvalidThenThrowIllegalArgumentException() {
		assertThatCode(() -> new BearerTokenError(TEST_ERROR_CODE, TEST_HTTP_STATUS, TEST_DESCRIPTION,
				TEST_URI, TEST_SCOPE + "\""))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("scope")
				.hasMessageContaining("RFC 6750");
	}
}
