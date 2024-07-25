/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.oauth2.jwt;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link JwtAuthTimeValidator}
 *
 * @author Max Batischev
 */
public class JwtAuthTimeValidatorTests {

	private static final Clock MOCK_NOW = Clock.fixed(Instant.ofEpochMilli(0), ZoneId.systemDefault());

	private static final long MAX_AGE_FIVE_MINS = 300L;

	private static final String ERROR_DESCRIPTION = "\"More recent authentication is required\", max_age=\"300\"";

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc9470#name-authentication-requirements";

	@Test
	public void validateWhenDifferenceBetweenCurrentTimeAndAuthTimeLessThanMaxAgeThenReturnsSuccess() {
		Instant authTime = Instant.now().minusSeconds(240);
		JwtAuthTimeValidator jwtValidator = new JwtAuthTimeValidator(MAX_AGE_FIVE_MINS);
		Jwt jwt = TestJwts.jwt().claim(JwtClaimNames.AUTH_TIME, authTime.getEpochSecond()).build();

		OAuth2TokenValidatorResult result = jwtValidator.validate(jwt);

		assertThat(result.hasErrors()).isFalse();
		assertThat(result).isEqualTo(OAuth2TokenValidatorResult.success());
	}

	@Test
	public void validateWhenDifferenceBetweenCurrentTimeAndAuthTimeGreaterThanMaxAgeThenReturnsError() {
		Instant authTime = Instant.now().minusSeconds(720);

		JwtAuthTimeValidator jwtValidator = new JwtAuthTimeValidator(MAX_AGE_FIVE_MINS);
		Jwt jwt = TestJwts.jwt().claim(JwtClaimNames.AUTH_TIME, authTime.getEpochSecond()).build();

		OAuth2TokenValidatorResult result = jwtValidator.validate(jwt);

		assertThat(result.hasErrors()).isTrue();
		// @formatter:off
		OAuth2Error error = result.getErrors().stream()
				.findAny()
				.get();
		// @formatter:on
		assertThat(error.getUri()).isEqualTo(ERROR_URI);
		assertThat(error.getDescription()).isEqualTo(ERROR_DESCRIPTION);
		assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INSUFFICIENT_USER_AUTHENTICATION);
	}

	@Test
	public void validateWhenConfiguredWithFixedClockThenValidatesUsingFixedTime() {
		Instant authTime = Instant.now(MOCK_NOW).minusSeconds(240);
		Jwt jwt = TestJwts.jwt().claim(JwtClaimNames.AUTH_TIME, authTime.getEpochSecond()).build();
		JwtAuthTimeValidator jwtValidator = new JwtAuthTimeValidator(MAX_AGE_FIVE_MINS);
		jwtValidator.setClock(MOCK_NOW);

		OAuth2TokenValidatorResult result = jwtValidator.validate(jwt);

		assertThat(result.hasErrors()).isFalse();
	}

	@Test
	public void validateWhenJwtIsNullThenThrowsIllegalArgumentException() {
		JwtAuthTimeValidator jwtValidator = new JwtAuthTimeValidator(MAX_AGE_FIVE_MINS);

		assertThatIllegalArgumentException().isThrownBy(() -> jwtValidator.validate(null));
	}

	@Test
	public void setClockWhenInvokedWithNullThenThrowsIllegalArgumentException() {
		JwtAuthTimeValidator jwtValidator = new JwtAuthTimeValidator(MAX_AGE_FIVE_MINS);
		assertThatIllegalArgumentException().isThrownBy(() -> jwtValidator.setClock(null));
	}

	@Test
	public void constructorWhenInvokedWithNullDurationThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new JwtAuthTimeValidator(MAX_AGE_FIVE_MINS, null));
	}

	@Test
	public void constructorWhenInvokedWithZeroMaxAgeThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new JwtAuthTimeValidator(0, Duration.ZERO));
	}

}
