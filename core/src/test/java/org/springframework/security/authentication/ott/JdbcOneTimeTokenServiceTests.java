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
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link JdbcOneTimeTokenService}.
 *
 * @author Max Batischev
 */
class JdbcOneTimeTokenServiceTests {

	private static final String USERNAME = "user";

	private static final String TOKEN_VALUE = "1234";

	private static final String ONE_TIME_TOKEN_SQL_RESOURCE = "org/springframework/security/core/ott/jdbc/one-time-tokens-schema.sql";

	private EmbeddedDatabase db;

	private JdbcOperations jdbcOperations;

	private JdbcOneTimeTokenService oneTimeTokenService;

	@BeforeEach
	void setUp() {
		this.db = createDb();
		this.jdbcOperations = new JdbcTemplate(this.db);
		this.oneTimeTokenService = new JdbcOneTimeTokenService(this.jdbcOperations);
	}

	@AfterEach
	void tearDown() throws Exception {
		this.db.shutdown();
		this.oneTimeTokenService.destroy();
	}

	private static EmbeddedDatabase createDb() {
		// @formatter:off
		return new EmbeddedDatabaseBuilder()
				.generateUniqueName(true)
				.setType(EmbeddedDatabaseType.HSQL)
				.setScriptEncoding("UTF-8")
				.addScript(ONE_TIME_TOKEN_SQL_RESOURCE)
				.build();
		// @formatter:on
	}

	@Test
	void constructorWhenJdbcOperationsIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new JdbcOneTimeTokenService(null))
				.withMessage("jdbcOperations cannot be null");
		// @formatter:on
	}

	@Test
	void generateWhenGenerateOneTimeTokenRequestIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.oneTimeTokenService.generate(null))
				.withMessage("generateOneTimeTokenRequest cannot be null");
		// @formatter:on
	}

	@Test
	void consumeWhenAuthenticationTokenIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.oneTimeTokenService.consume(null))
				.withMessage("authenticationToken cannot be null");
		// @formatter:on
	}

	@Test
	void generateThenTokenValueShouldBeValidUuidAndProvidedUsernameIsUsed() {
		OneTimeToken oneTimeToken = this.oneTimeTokenService.generate(new GenerateOneTimeTokenRequest(USERNAME));

		OneTimeToken persistedOneTimeToken = this.oneTimeTokenService
			.consume(new OneTimeTokenAuthenticationToken(oneTimeToken.getTokenValue()));
		assertThat(persistedOneTimeToken).isNotNull();
		assertThat(persistedOneTimeToken.getUsername()).isNotNull();
		assertThat(persistedOneTimeToken.getTokenValue()).isNotNull();
		assertThat(persistedOneTimeToken.getExpiresAt()).isNotNull();
	}

	@Test
	void consumeWhenTokenExistsThenReturnItself() {
		OneTimeToken oneTimeToken = this.oneTimeTokenService.generate(new GenerateOneTimeTokenRequest(USERNAME));
		OneTimeTokenAuthenticationToken authenticationToken = new OneTimeTokenAuthenticationToken(
				oneTimeToken.getTokenValue());

		OneTimeToken consumedOneTimeToken = this.oneTimeTokenService.consume(authenticationToken);

		assertThat(consumedOneTimeToken).isNotNull();
		assertThat(consumedOneTimeToken.getUsername()).isNotNull();
		assertThat(consumedOneTimeToken.getTokenValue()).isNotNull();
		assertThat(consumedOneTimeToken.getExpiresAt()).isNotNull();
		OneTimeToken persistedOneTimeToken = this.oneTimeTokenService
			.consume(new OneTimeTokenAuthenticationToken(consumedOneTimeToken.getTokenValue()));
		assertThat(persistedOneTimeToken).isNull();
	}

	@Test
	void consumeWhenTokenDoesNotExistsThenReturnNull() {
		OneTimeTokenAuthenticationToken authenticationToken = new OneTimeTokenAuthenticationToken(TOKEN_VALUE);

		OneTimeToken consumedOneTimeToken = this.oneTimeTokenService.consume(authenticationToken);

		assertThat(consumedOneTimeToken).isNull();
	}

	@Test
	void consumeWhenTokenIsExpiredThenReturnNull() {
		GenerateOneTimeTokenRequest request = new GenerateOneTimeTokenRequest(USERNAME);
		OneTimeToken generated = this.oneTimeTokenService.generate(request);
		OneTimeTokenAuthenticationToken authenticationToken = new OneTimeTokenAuthenticationToken(
				generated.getTokenValue());
		Clock tenMinutesFromNow = Clock.fixed(Instant.now().plus(10, ChronoUnit.MINUTES), ZoneOffset.UTC);
		this.oneTimeTokenService.setClock(tenMinutesFromNow);

		OneTimeToken consumed = this.oneTimeTokenService.consume(authenticationToken);
		assertThat(consumed).isNull();
	}

	@Test
	void cleanupExpiredTokens() {
		Clock clock = mock(Clock.class);
		Instant tenMinutesAgo = Instant.now().minus(Duration.ofMinutes(10));
		given(clock.instant()).willReturn(tenMinutesAgo);
		this.oneTimeTokenService.setClock(clock);
		OneTimeToken token1 = this.oneTimeTokenService.generate(new GenerateOneTimeTokenRequest(USERNAME));
		OneTimeToken token2 = this.oneTimeTokenService.generate(new GenerateOneTimeTokenRequest(USERNAME));

		this.oneTimeTokenService.cleanupExpiredTokens();

		OneTimeToken deletedOneTimeToken1 = this.oneTimeTokenService
			.consume(new OneTimeTokenAuthenticationToken(token1.getTokenValue()));
		OneTimeToken deletedOneTimeToken2 = this.oneTimeTokenService
			.consume(new OneTimeTokenAuthenticationToken(token2.getTokenValue()));
		assertThat(deletedOneTimeToken1).isNull();
		assertThat(deletedOneTimeToken2).isNull();
	}

	@Test
	void setCleanupChronWhenNullThenNoException() {
		this.oneTimeTokenService.setCleanupCron(null);
	}

	@Test
	void setCleanupChronWhenAlreadyNullThenNoException() {
		this.oneTimeTokenService.setCleanupCron(null);
		this.oneTimeTokenService.setCleanupCron(null);
	}

}
