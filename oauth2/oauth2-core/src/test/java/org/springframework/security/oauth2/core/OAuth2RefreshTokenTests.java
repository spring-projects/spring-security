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

package org.springframework.security.oauth2.core;

import java.time.Instant;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link OAuth2RefreshToken}.
 *
 * @author Alexey Nesterov
 */
public class OAuth2RefreshTokenTests {

	private static final String TOKEN_VALUE = "refresh-token";

	private static final Instant ISSUED_AT = Instant.now();

	private static final Instant EXPIRES_AT = Instant.from(ISSUED_AT).plusSeconds(60);

	@Test
	public void constructorWhenTokenValueIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new OAuth2RefreshToken(null, ISSUED_AT, EXPIRES_AT))
				.withMessage("tokenValue cannot be empty");
	}

	@Test
	public void constructorWhenIssuedAtAfterExpiresAtThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(
						() -> new OAuth2RefreshToken(TOKEN_VALUE, Instant.from(EXPIRES_AT).plusSeconds(1), EXPIRES_AT))
				.withMessage("expiresAt must be after issuedAt");
	}

	@Test
	public void constructorWhenExpiresAtBeforeIssuedAtThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(
						() -> new OAuth2RefreshToken(TOKEN_VALUE, ISSUED_AT, Instant.from(ISSUED_AT).minusSeconds(1)))
				.withMessage("expiresAt must be after issuedAt");
	}

	@Test
	public void constructorWhenAllParametersProvidedAndValidThenCreated() {
		OAuth2RefreshToken token = new OAuth2RefreshToken(TOKEN_VALUE, ISSUED_AT, EXPIRES_AT);
		assertThat(token.getTokenValue()).isEqualTo(TOKEN_VALUE);
		assertThat(token.getIssuedAt()).isEqualTo(ISSUED_AT);
		assertThat(token.getExpiresAt()).isEqualTo(EXPIRES_AT);
	}

}
