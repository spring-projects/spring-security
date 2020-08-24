/*
 * Copyright 2002-2017 the original author or authors.
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

package org.springframework.security.oauth2.core;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OAuth2Error}.
 *
 * @author Joe Grandja
 */
public class OAuth2ErrorTests {

	private static final String ERROR_CODE = "error-code";

	private static final String ERROR_DESCRIPTION = "error-description";

	private static final String ERROR_URI = "error-uri";

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenErrorCodeIsNullThenThrowIllegalArgumentException() {
		new OAuth2Error(null, ERROR_DESCRIPTION, ERROR_URI);
	}

	@Test
	public void constructorWhenAllParametersProvidedAndValidThenCreated() {
		OAuth2Error error = new OAuth2Error(ERROR_CODE, ERROR_DESCRIPTION, ERROR_URI);
		assertThat(error.getErrorCode()).isEqualTo(ERROR_CODE);
		assertThat(error.getDescription()).isEqualTo(ERROR_DESCRIPTION);
		assertThat(error.getUri()).isEqualTo(ERROR_URI);
	}

}
