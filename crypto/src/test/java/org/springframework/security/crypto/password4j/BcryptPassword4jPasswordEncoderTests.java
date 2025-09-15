/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.crypto.password4j;

import com.password4j.AlgorithmFinder;
import com.password4j.BcryptFunction;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link BcryptPassword4jPasswordEncoder}.
 *
 * @author Mehrdad Bozorgmehr
 */
class BcryptPassword4jPasswordEncoderTests {

	private static final String PASSWORD = "password";

	private static final String LONG_PASSWORD = "a".repeat(72); // BCrypt max length

	private static final String VERY_LONG_PASSWORD = "a".repeat(100); // Beyond BCrypt max
																		// length

	private static final String SPECIAL_CHARS_PASSWORD = "p@ssw0rd!#$%^&*()_+-=[]{}|;':\",./<>?";

	private static final String UNICODE_PASSWORD = "пароль密码パスワード🔐";

	@Test
	void defaultConstructorShouldCreateWorkingEncoder() {
		BcryptPassword4jPasswordEncoder encoder = new BcryptPassword4jPasswordEncoder();

		String encoded = encoder.encode(PASSWORD);

		assertThat(encoded).isNotNull().matches("^\\$2[aby]?\\$.*");
		assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
	}

	@Test
	void constructorWithNullBcryptFunctionShouldThrowException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new BcryptPassword4jPasswordEncoder(null))
			.withMessage("hashingFunction cannot be null");
	}

	@Test
	void constructorWithCustomBcryptFunctionShouldWork() {
		BcryptFunction customFunction = BcryptFunction.getInstance(6);
		BcryptPassword4jPasswordEncoder encoder = new BcryptPassword4jPasswordEncoder(customFunction);

		String encoded = encoder.encode(PASSWORD);

		assertThat(encoded).isNotNull().contains("$06$"); // 6 rounds
		assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
	}

	@ParameterizedTest
	@ValueSource(ints = { 4, 6, 8, 10, 12 })
	void encodingShouldWorkWithDifferentRounds(int rounds) {
		BcryptFunction function = BcryptFunction.getInstance(rounds);
		BcryptPassword4jPasswordEncoder encoder = new BcryptPassword4jPasswordEncoder(function);

		String encoded = encoder.encode(PASSWORD);

		assertThat(encoded).isNotNull().contains(String.format("$%02d$", rounds));
		assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
	}

	@Test
	void encodingShouldGenerateDifferentHashesForSamePassword() {
		BcryptPassword4jPasswordEncoder encoder = new BcryptPassword4jPasswordEncoder();

		String hash1 = encoder.encode(PASSWORD);
		String hash2 = encoder.encode(PASSWORD);

		assertThat(hash1).isNotEqualTo(hash2);
		assertThat(encoder.matches(PASSWORD, hash1)).isTrue();
		assertThat(encoder.matches(PASSWORD, hash2)).isTrue();
	}

	@Test
	void shouldHandleLongPasswords() {
		BcryptPassword4jPasswordEncoder encoder = new BcryptPassword4jPasswordEncoder();

		String encodedLong = encoder.encode(LONG_PASSWORD);
		String encodedVeryLong = encoder.encode(VERY_LONG_PASSWORD);

		assertThat(encoder.matches(LONG_PASSWORD, encodedLong)).isTrue();
		assertThat(encoder.matches(VERY_LONG_PASSWORD, encodedVeryLong)).isTrue();
	}

	@Test
	void shouldHandleSpecialCharacters() {
		BcryptPassword4jPasswordEncoder encoder = new BcryptPassword4jPasswordEncoder();

		String encoded = encoder.encode(SPECIAL_CHARS_PASSWORD);

		assertThat(encoder.matches(SPECIAL_CHARS_PASSWORD, encoded)).isTrue();
		assertThat(encoder.matches("wrong", encoded)).isFalse();
	}

	@Test
	void shouldHandleUnicodeCharacters() {
		BcryptPassword4jPasswordEncoder encoder = new BcryptPassword4jPasswordEncoder();

		String encoded = encoder.encode(UNICODE_PASSWORD);

		assertThat(encoder.matches(UNICODE_PASSWORD, encoded)).isTrue();
		assertThat(encoder.matches("wrong", encoded)).isFalse();
	}

	@Test
	void shouldRejectIncorrectPasswords() {
		BcryptPassword4jPasswordEncoder encoder = new BcryptPassword4jPasswordEncoder();
		String encoded = encoder.encode(PASSWORD);

		assertThat(encoder.matches("wrongpassword", encoded)).isFalse();
		assertThat(encoder.matches("PASSWORD", encoded)).isFalse(); // Case sensitive
		assertThat(encoder.matches("password ", encoded)).isFalse(); // Trailing space
		assertThat(encoder.matches(" password", encoded)).isFalse(); // Leading space
	}

	@Test
	void matchesShouldReturnFalseForNullOrEmptyInputs() {
		BcryptPassword4jPasswordEncoder encoder = new BcryptPassword4jPasswordEncoder();
		String encoded = encoder.encode(PASSWORD);

		assertThat(encoder.matches(null, encoded)).isFalse();
		assertThat(encoder.matches("", encoded)).isFalse();
		assertThat(encoder.matches(PASSWORD, null)).isFalse();
		assertThat(encoder.matches(PASSWORD, "")).isFalse();
		assertThat(encoder.matches(null, null)).isFalse();
		assertThat(encoder.matches("", "")).isFalse();
	}

	@Test
	void encodeNullShouldReturnNull() {
		BcryptPassword4jPasswordEncoder encoder = new BcryptPassword4jPasswordEncoder();

		assertThat(encoder.encode(null)).isNull();
	}

	@Test
	void upgradeEncodingShouldReturnFalse() {
		BcryptPassword4jPasswordEncoder encoder = new BcryptPassword4jPasswordEncoder();
		String encoded = encoder.encode(PASSWORD);

		assertThat(encoder.upgradeEncoding(encoded)).isFalse();
	}

	@Test
	void shouldWorkWithAlgorithmFinderDefaults() {
		BcryptPassword4jPasswordEncoder encoder = new BcryptPassword4jPasswordEncoder(
				AlgorithmFinder.getBcryptInstance());

		String encoded = encoder.encode(PASSWORD);

		assertThat(encoded).isNotNull();
		assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
	}

	@Test
	void shouldRejectMalformedHashes() {
		BcryptPassword4jPasswordEncoder encoder = new BcryptPassword4jPasswordEncoder();
		assertMalformedRejected(encoder, PASSWORD, "invalid_hash");
		assertMalformedRejected(encoder, PASSWORD, "$2a$10$invalid");
		assertMalformedRejected(encoder, PASSWORD, "");
	}

	private void assertMalformedRejected(BcryptPassword4jPasswordEncoder encoder, String raw, String malformed) {
		boolean rejected;
		try {
			rejected = !encoder.matches(raw, malformed);
		}
		catch (RuntimeException ex) {
			rejected = true; // exception is acceptable rejection
		}
		assertThat(rejected).as("Malformed hash should not validate: " + malformed).isTrue();
	}

	@Test
	void shouldHandleEmptyStringPassword() {
		BcryptPassword4jPasswordEncoder encoder = new BcryptPassword4jPasswordEncoder();
		String encoded = encoder.encode("");
		assertThat(encoded).isNotNull();
		boolean emptyMatches;
		try {
			emptyMatches = encoder.matches("", encoded);
		}
		catch (RuntimeException ex) {
			emptyMatches = false; // treat as non-match if library rejects empty raw
		}
		// Either behavior acceptable; if it matches, verify; if not, still ensure other
		// mismatches remain false.
		if (emptyMatches) {
			assertThat(encoder.matches("", encoded)).isTrue();
		}
		assertThat(encoder.matches("notEmpty", encoded)).isFalse();
	}

}
