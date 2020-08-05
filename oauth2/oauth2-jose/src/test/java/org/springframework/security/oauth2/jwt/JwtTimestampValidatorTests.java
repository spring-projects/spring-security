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
package org.springframework.security.oauth2.jwt;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.Test;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.EXP;
import static org.springframework.security.oauth2.jwt.TestJwts.jwt;

/**
 * Tests verifying {@link JwtTimestampValidator}
 *
 * @author Josh Cummings
 */
public class JwtTimestampValidatorTests {

	private static final Clock MOCK_NOW = Clock.fixed(Instant.ofEpochMilli(0), ZoneId.systemDefault());

	private static final String MOCK_TOKEN_VALUE = "token";

	private static final Instant MOCK_ISSUED_AT = Instant.MIN;

	private static final Map<String, Object> MOCK_HEADER = Collections.singletonMap("alg", JwsAlgorithms.RS256);

	private static final Map<String, Object> MOCK_CLAIM_SET = Collections.singletonMap("some", "claim");

	@Test
	public void validateWhenJwtIsExpiredThenErrorMessageIndicatesExpirationTime() {
		Instant oneHourAgo = Instant.now().minusSeconds(3600);

		Jwt jwt = jwt().expiresAt(oneHourAgo).build();

		JwtTimestampValidator jwtValidator = new JwtTimestampValidator();

		Collection<OAuth2Error> details = jwtValidator.validate(jwt).getErrors();
		Collection<String> messages = details.stream().map(OAuth2Error::getDescription).collect(Collectors.toList());

		assertThat(messages).contains("Jwt expired at " + oneHourAgo);
	}

	@Test
	public void validateWhenJwtIsTooEarlyThenErrorMessageIndicatesNotBeforeTime() {
		Instant oneHourFromNow = Instant.now().plusSeconds(3600);

		Jwt jwt = jwt().notBefore(oneHourFromNow).build();

		JwtTimestampValidator jwtValidator = new JwtTimestampValidator();

		Collection<OAuth2Error> details = jwtValidator.validate(jwt).getErrors();
		Collection<String> messages = details.stream().map(OAuth2Error::getDescription).collect(Collectors.toList());

		assertThat(messages).contains("Jwt used before " + oneHourFromNow);
	}

	@Test
	public void validateWhenConfiguredWithClockSkewThenValidatesUsingThatSkew() {
		Duration oneDayOff = Duration.ofDays(1);
		JwtTimestampValidator jwtValidator = new JwtTimestampValidator(oneDayOff);

		Instant now = Instant.now();
		Instant almostOneDayAgo = now.minus(oneDayOff).plusSeconds(10);
		Instant almostOneDayFromNow = now.plus(oneDayOff).minusSeconds(10);
		Instant justOverOneDayAgo = now.minus(oneDayOff).minusSeconds(10);
		Instant justOverOneDayFromNow = now.plus(oneDayOff).plusSeconds(10);

		Jwt jwt = jwt().expiresAt(almostOneDayAgo).notBefore(almostOneDayFromNow).build();

		assertThat(jwtValidator.validate(jwt).hasErrors()).isFalse();

		jwt = jwt().expiresAt(justOverOneDayAgo).build();

		OAuth2TokenValidatorResult result = jwtValidator.validate(jwt);
		Collection<String> messages = result.getErrors().stream().map(OAuth2Error::getDescription)
				.collect(Collectors.toList());

		assertThat(result.hasErrors()).isTrue();
		assertThat(messages).contains("Jwt expired at " + justOverOneDayAgo);

		jwt = jwt().notBefore(justOverOneDayFromNow).build();

		result = jwtValidator.validate(jwt);
		messages = result.getErrors().stream().map(OAuth2Error::getDescription).collect(Collectors.toList());

		assertThat(result.hasErrors()).isTrue();
		assertThat(messages).contains("Jwt used before " + justOverOneDayFromNow);

	}

	@Test
	public void validateWhenConfiguredWithFixedClockThenValidatesUsingFixedTime() {
		Jwt jwt = jwt().expiresAt(Instant.now(MOCK_NOW)).build();

		JwtTimestampValidator jwtValidator = new JwtTimestampValidator(Duration.ofNanos(0));
		jwtValidator.setClock(MOCK_NOW);

		assertThat(jwtValidator.validate(jwt).hasErrors()).isFalse();

		jwt = jwt().notBefore(Instant.now(MOCK_NOW)).build();

		assertThat(jwtValidator.validate(jwt).hasErrors()).isFalse();
	}

	@Test
	public void validateWhenNeitherExpiryNorNotBeforeIsSpecifiedThenReturnsSuccessfulResult() {
		Jwt jwt = jwt().claims(c -> c.remove(EXP)).build();

		JwtTimestampValidator jwtValidator = new JwtTimestampValidator();
		assertThat(jwtValidator.validate(jwt).hasErrors()).isFalse();
	}

	@Test
	public void validateWhenNotBeforeIsValidAndExpiryIsNotSpecifiedThenReturnsSuccessfulResult() {
		Jwt jwt = jwt().claims(c -> c.remove(EXP)).notBefore(Instant.MIN).build();

		JwtTimestampValidator jwtValidator = new JwtTimestampValidator();
		assertThat(jwtValidator.validate(jwt).hasErrors()).isFalse();
	}

	@Test
	public void validateWhenExpiryIsValidAndNotBeforeIsNotSpecifiedThenReturnsSuccessfulResult() {
		Jwt jwt = jwt().build();

		JwtTimestampValidator jwtValidator = new JwtTimestampValidator();
		assertThat(jwtValidator.validate(jwt).hasErrors()).isFalse();
	}

	@Test
	public void validateWhenBothExpiryAndNotBeforeAreValidThenReturnsSuccessfulResult() {
		Jwt jwt = jwt().expiresAt(Instant.now(MOCK_NOW)).notBefore(Instant.now(MOCK_NOW)).build();

		JwtTimestampValidator jwtValidator = new JwtTimestampValidator(Duration.ofNanos(0));
		jwtValidator.setClock(MOCK_NOW);

		assertThat(jwtValidator.validate(jwt).hasErrors()).isFalse();
	}

	@Test
	public void setClockWhenInvokedWithNullThenThrowsIllegalArgumentException() {
		JwtTimestampValidator jwtValidator = new JwtTimestampValidator();

		assertThatCode(() -> jwtValidator.setClock(null)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenInvokedWithNullDurationThenThrowsIllegalArgumentException() {
		assertThatCode(() -> new JwtTimestampValidator(null)).isInstanceOf(IllegalArgumentException.class);
	}

}
