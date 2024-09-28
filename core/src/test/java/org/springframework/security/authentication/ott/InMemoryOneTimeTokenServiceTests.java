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

package org.springframework.security.authentication.ott;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNoException;

/**
 * Tests for {@link InMemoryOneTimeTokenService}
 *
 * @author Marcus da Coregio
 */
class InMemoryOneTimeTokenServiceTests {

	InMemoryOneTimeTokenService oneTimeTokenService = new InMemoryOneTimeTokenService();

	@Test
	void generateThenTokenValueShouldBeValidUuidAndProvidedUsernameIsUsed() {
		GenerateOneTimeTokenRequest request = new GenerateOneTimeTokenRequest("user");
		OneTimeToken oneTimeToken = this.oneTimeTokenService.generate(request);
		assertThatNoException().isThrownBy(() -> UUID.fromString(oneTimeToken.getTokenValue()));
		assertThat(request.getUsername()).isEqualTo("user");
	}

	@Test
	void consumeWhenTokenDoesNotExistsThenNull() {
		OneTimeTokenAuthenticationToken authenticationToken = new OneTimeTokenAuthenticationToken("123");
		OneTimeToken oneTimeToken = this.oneTimeTokenService.consume(authenticationToken);
		assertThat(oneTimeToken).isNull();
	}

	@Test
	void consumeWhenTokenExistsThenReturnItself() {
		GenerateOneTimeTokenRequest request = new GenerateOneTimeTokenRequest("user");
		OneTimeToken generated = this.oneTimeTokenService.generate(request);
		OneTimeTokenAuthenticationToken authenticationToken = new OneTimeTokenAuthenticationToken(
				generated.getTokenValue());
		OneTimeToken consumed = this.oneTimeTokenService.consume(authenticationToken);
		assertThat(consumed.getTokenValue()).isEqualTo(generated.getTokenValue());
		assertThat(consumed.getUsername()).isEqualTo(generated.getUsername());
		assertThat(consumed.getExpiresAt()).isEqualTo(generated.getExpiresAt());
	}

	@Test
	void consumeWhenTokenIsExpiredThenReturnNull() {
		GenerateOneTimeTokenRequest request = new GenerateOneTimeTokenRequest("user");
		OneTimeToken generated = this.oneTimeTokenService.generate(request);
		OneTimeTokenAuthenticationToken authenticationToken = new OneTimeTokenAuthenticationToken(
				generated.getTokenValue());
		Clock tenMinutesFromNow = Clock.fixed(Instant.now().plus(10, ChronoUnit.MINUTES), ZoneOffset.UTC);
		this.oneTimeTokenService.setClock(tenMinutesFromNow);
		OneTimeToken consumed = this.oneTimeTokenService.consume(authenticationToken);
		assertThat(consumed).isNull();
	}

	@Test
	void generateWhenMoreThan100TokensThenClearExpired() {
		// @formatter:off
		List<OneTimeToken> toExpire = generate(50); // 50 tokens will expire in 5 minutes from now
		Clock twoMinutesFromNow = Clock.fixed(Instant.now().plus(2, ChronoUnit.MINUTES), ZoneOffset.UTC);
		this.oneTimeTokenService.setClock(twoMinutesFromNow);
		List<OneTimeToken> toKeep = generate(50); // 50 tokens will expire in 7 minutes from now
		Clock sixMinutesFromNow = Clock.fixed(Instant.now().plus(6, ChronoUnit.MINUTES), ZoneOffset.UTC);
		this.oneTimeTokenService.setClock(sixMinutesFromNow);

		assertThat(toExpire)
			.extracting(
					(token) -> this.oneTimeTokenService.consume(new OneTimeTokenAuthenticationToken(token.getTokenValue())))
			.containsOnlyNulls();

		assertThat(toKeep)
			.extracting(
					(token) -> this.oneTimeTokenService.consume(new OneTimeTokenAuthenticationToken(token.getTokenValue())))
			.noneMatch(Objects::isNull);
		// @formatter:on
	}

	@Test
	void setClockWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.oneTimeTokenService.setClock(null))
				.withMessage("clock cannot be null");
		// @formatter:on
	}

	private List<OneTimeToken> generate(int howMany) {
		List<OneTimeToken> generated = new ArrayList<>(howMany);
		for (int i = 0; i < howMany; i++) {
			OneTimeToken oneTimeToken = this.oneTimeTokenService
				.generate(new GenerateOneTimeTokenRequest("generated" + i));
			generated.add(oneTimeToken);
		}
		return generated;
	}

}
