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
package org.springframework.security.oauth2.jwt;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;

import org.junit.Test;

import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * @author Josh Cummings
 * @since 5.1
 */
public class JwtIssuerValidatorTests {
	private static final String MOCK_TOKEN = "token";
	private static final Instant MOCK_ISSUED_AT = Instant.MIN;
	private static final Instant MOCK_EXPIRES_AT = Instant.MAX;
	private static final Map<String, Object> MOCK_HEADERS =
			Collections.singletonMap("alg", JwsAlgorithms.RS256);

	private static final String ISSUER = "https://issuer";

	private final JwtIssuerValidator validator = new JwtIssuerValidator(ISSUER);

	@Test
	public void validateWhenIssuerMatchesThenReturnsSuccess() {
		Jwt jwt = new Jwt(
				MOCK_TOKEN,
				MOCK_ISSUED_AT,
				MOCK_EXPIRES_AT,
				MOCK_HEADERS,
				Collections.singletonMap("iss", ISSUER));

		assertThat(this.validator.validate(jwt))
				.isEqualTo(OAuth2TokenValidatorResult.success());
	}

	@Test
	public void validateWhenIssuerMismatchesThenReturnsError() {
		Jwt jwt = new Jwt(
				MOCK_TOKEN,
				MOCK_ISSUED_AT,
				MOCK_EXPIRES_AT,
				MOCK_HEADERS,
				Collections.singletonMap(JwtClaimNames.ISS, "https://other"));

		OAuth2TokenValidatorResult result = this.validator.validate(jwt);

		assertThat(result.getErrors()).isNotEmpty();
	}

	@Test
	public void validateWhenJwtHasNoIssuerThenReturnsError() {
		Jwt jwt = new Jwt(
				MOCK_TOKEN,
				MOCK_ISSUED_AT,
				MOCK_EXPIRES_AT,
				MOCK_HEADERS,
				Collections.singletonMap(JwtClaimNames.AUD, "https://aud"));

		OAuth2TokenValidatorResult result = this.validator.validate(jwt);
		assertThat(result.getErrors()).isNotEmpty();
	}

	// gh-6073
	@Test
	public void validateWhenIssuerMatchesAndIsNotAUriThenReturnsSuccess() {
		Jwt jwt = new Jwt(
				MOCK_TOKEN,
				MOCK_ISSUED_AT,
				MOCK_EXPIRES_AT,
				MOCK_HEADERS,
				Collections.singletonMap(JwtClaimNames.ISS, "issuer"));
		JwtIssuerValidator validator = new JwtIssuerValidator("issuer");

		assertThat(validator.validate(jwt))
				.isEqualTo(OAuth2TokenValidatorResult.success());
	}

	@Test
	public void validateWhenJwtIsNullThenThrowsIllegalArgumentException() {
		assertThatCode(() -> this.validator.validate(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenNullIssuerIsGivenThenThrowsIllegalArgumentException() {
		assertThatCode(() -> new JwtIssuerValidator(null))
				.isInstanceOf(IllegalArgumentException.class);
	}
}
