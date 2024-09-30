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

package org.springframework.security.authentication.ott.reactive;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

/**
 * Tests for {@link InMemoryReactiveOneTimeTokenService}
 *
 * @author Max Batischev
 */
public class InMemoryReactiveOneTimeTokenServiceTests {

	private final InMemoryReactiveOneTimeTokenService oneTimeTokenService = new InMemoryReactiveOneTimeTokenService();

	private static final String USERNAME = "user";

	private static final String TOKEN = "token";

	@Test
	void generateThenTokenValueShouldBeValidUuidAndProvidedUsernameIsUsed() {
		GenerateOneTimeTokenRequest request = new GenerateOneTimeTokenRequest(USERNAME);

		OneTimeToken oneTimeToken = this.oneTimeTokenService.generate(request).block();

		assertThatNoException().isThrownBy(() -> UUID.fromString(oneTimeToken.getTokenValue()));
		assertThat(oneTimeToken.getUsername()).isEqualTo(USERNAME);
	}

	@Test
	void consumeWhenTokenDoesNotExistThenNull() {
		OneTimeTokenAuthenticationToken authenticationToken = new OneTimeTokenAuthenticationToken(TOKEN);

		OneTimeToken oneTimeToken = this.oneTimeTokenService.consume(authenticationToken).block();

		assertThat(oneTimeToken).isNull();
	}

	@Test
	void consumeWhenTokenExistsThenReturnItself() {
		GenerateOneTimeTokenRequest request = new GenerateOneTimeTokenRequest(USERNAME);
		OneTimeToken generated = this.oneTimeTokenService.generate(request).block();
		OneTimeTokenAuthenticationToken authenticationToken = new OneTimeTokenAuthenticationToken(
				generated.getTokenValue());

		OneTimeToken consumed = this.oneTimeTokenService.consume(authenticationToken).block();

		assertThat(consumed.getTokenValue()).isEqualTo(generated.getTokenValue());
		assertThat(consumed.getUsername()).isEqualTo(generated.getUsername());
		assertThat(consumed.getExpiresAt()).isEqualTo(generated.getExpiresAt());
	}

	@Test
	void consumeWhenTokenIsExpiredThenReturnNull() {
		GenerateOneTimeTokenRequest request = new GenerateOneTimeTokenRequest(USERNAME);
		OneTimeToken generated = this.oneTimeTokenService.generate(request).block();
		OneTimeTokenAuthenticationToken authenticationToken = new OneTimeTokenAuthenticationToken(
				generated.getTokenValue());
		Clock tenMinutesFromNow = Clock.fixed(Instant.now().plus(10, ChronoUnit.MINUTES), ZoneOffset.UTC);
		this.oneTimeTokenService.setClock(tenMinutesFromNow);

		OneTimeToken consumed = this.oneTimeTokenService.consume(authenticationToken).block();

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
				.extracting((token) -> this.oneTimeTokenService.consume(new OneTimeTokenAuthenticationToken(token.getTokenValue()))
								.block()
				)
				.containsOnlyNulls();

		assertThat(toKeep)
				.extracting((token) -> this.oneTimeTokenService.consume(new OneTimeTokenAuthenticationToken(token.getTokenValue()))
								.block()
				)
				.noneMatch(Objects::isNull);
		// @formatter:on
	}

	private List<OneTimeToken> generate(int howMany) {
		List<OneTimeToken> generated = new ArrayList<>(howMany);
		for (int i = 0; i < howMany; i++) {
			OneTimeToken oneTimeToken = this.oneTimeTokenService
				.generate(new GenerateOneTimeTokenRequest("generated" + i))
				.block();
			generated.add(oneTimeToken);
		}
		return generated;
	}

}
