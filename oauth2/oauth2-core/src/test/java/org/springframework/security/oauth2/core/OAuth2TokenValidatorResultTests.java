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
package org.springframework.security.oauth2.core;

import org.junit.Test;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for verifying {@link OAuth2TokenValidatorResult}
 *
 * @author Josh Cummings
 */
public class OAuth2TokenValidatorResultTests {
	private static final OAuth2Error DETAIL = new OAuth2Error(
			"error", "description", "uri");

	@Test
	public void successWhenInvokedThenReturnsSuccessfulResult() {
		OAuth2TokenValidatorResult success = OAuth2TokenValidatorResult.success();
		assertThat(success.hasErrors()).isFalse();
	}

	@Test
	public void failureWhenInvokedWithDetailReturnsFailureResultIncludingDetail() {
		OAuth2TokenValidatorResult failure = OAuth2TokenValidatorResult.failure(DETAIL);

		assertThat(failure.hasErrors()).isTrue();
		assertThat(failure.getErrors()).containsExactly(DETAIL);
	}

	@Test
	public void failureWhenInvokedWithMultipleDetailsReturnsFailureResultIncludingAll() {
		OAuth2TokenValidatorResult failure = OAuth2TokenValidatorResult.failure(DETAIL, DETAIL);

		assertThat(failure.hasErrors()).isTrue();
		assertThat(failure.getErrors()).containsExactly(DETAIL, DETAIL);
	}
}
