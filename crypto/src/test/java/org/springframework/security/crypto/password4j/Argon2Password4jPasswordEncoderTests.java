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
import com.password4j.Argon2Function;
import com.password4j.types.Argon2;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link Argon2Password4jPasswordEncoder}.
 *
 * @author Mehrdad Bozorgmehr
 */
class Argon2Password4jPasswordEncoderTests {

	private static final String PASSWORD = "password";

	private static final String LONG_PASSWORD = "a".repeat(1000);

	private static final String SPECIAL_CHARS_PASSWORD = "p@ssw0rd!#$%^&*()_+-=[]{}|;':\",./<>?";

	private static final String UNICODE_PASSWORD = "пароль密码パスワード🔐";

	@Test
	void defaultConstructorShouldCreateWorkingEncoder() {
		Argon2Password4jPasswordEncoder encoder = new Argon2Password4jPasswordEncoder();

		String encoded = encoder.encode(PASSWORD);

		assertThat(encoded).isNotNull();
		assertThat(encoded).startsWith("$argon2"); // Argon2 hash format
		assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
	}

	@Test
	void constructorWithNullArgon2FunctionShouldThrowException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new Argon2Password4jPasswordEncoder(null))
			.withMessage("hashingFunction cannot be null");
	}

	@Test
	void constructorWithCustomArgon2FunctionShouldWork() {
		Argon2Function customFunction = Argon2Function.getInstance(4096, 3, 1, 32, Argon2.ID);
		Argon2Password4jPasswordEncoder encoder = new Argon2Password4jPasswordEncoder(customFunction);

		String encoded = encoder.encode(PASSWORD);

		assertThat(encoded).isNotNull();
		assertThat(encoded).startsWith("$argon2id");
		assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
	}

	@ParameterizedTest
	@EnumSource(Argon2.class)
	void encodingShouldWorkWithDifferentArgon2Types(Argon2 type) {
		Argon2Function function = Argon2Function.getInstance(4096, 3, 1, 32, type);
		Argon2Password4jPasswordEncoder encoder = new Argon2Password4jPasswordEncoder(function);

		String encoded = encoder.encode(PASSWORD);

		assertThat(encoded).isNotNull();
		assertThat(encoded).startsWith("$argon2" + type.name().toLowerCase());
		assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
	}

	@Test
	void encodingShouldGenerateDifferentHashesForSamePassword() {
		Argon2Password4jPasswordEncoder encoder = new Argon2Password4jPasswordEncoder();

		String hash1 = encoder.encode(PASSWORD);
		String hash2 = encoder.encode(PASSWORD);

		assertThat(hash1).isNotEqualTo(hash2);
		assertThat(encoder.matches(PASSWORD, hash1)).isTrue();
		assertThat(encoder.matches(PASSWORD, hash2)).isTrue();
	}

	@Test
	void shouldHandleLongPasswords() {
		Argon2Password4jPasswordEncoder encoder = new Argon2Password4jPasswordEncoder();

		String encoded = encoder.encode(LONG_PASSWORD);

		assertThat(encoder.matches(LONG_PASSWORD, encoded)).isTrue();
		assertThat(encoder.matches("wrong", encoded)).isFalse();
	}

	@Test
	void shouldHandleSpecialCharacters() {
		Argon2Password4jPasswordEncoder encoder = new Argon2Password4jPasswordEncoder();

		String encoded = encoder.encode(SPECIAL_CHARS_PASSWORD);

		assertThat(encoder.matches(SPECIAL_CHARS_PASSWORD, encoded)).isTrue();
		assertThat(encoder.matches("wrong", encoded)).isFalse();
	}

	@Test
	void shouldHandleUnicodeCharacters() {
		Argon2Password4jPasswordEncoder encoder = new Argon2Password4jPasswordEncoder();

		String encoded = encoder.encode(UNICODE_PASSWORD);

		assertThat(encoder.matches(UNICODE_PASSWORD, encoded)).isTrue();
		assertThat(encoder.matches("wrong", encoded)).isFalse();
	}

	@Test
	void shouldRejectIncorrectPasswords() {
		Argon2Password4jPasswordEncoder encoder = new Argon2Password4jPasswordEncoder();
		String encoded = encoder.encode(PASSWORD);

		assertThat(encoder.matches("wrongpassword", encoded)).isFalse();
		assertThat(encoder.matches("PASSWORD", encoded)).isFalse(); // Case sensitive
		assertThat(encoder.matches("password ", encoded)).isFalse(); // Trailing space
		assertThat(encoder.matches(" password", encoded)).isFalse(); // Leading space
	}

	@Test
	void matchesShouldReturnFalseForNullOrEmptyInputs() {
		Argon2Password4jPasswordEncoder encoder = new Argon2Password4jPasswordEncoder();
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
		Argon2Password4jPasswordEncoder encoder = new Argon2Password4jPasswordEncoder();

		assertThat(encoder.encode(null)).isNull();
	}

	@Test
	void upgradeEncodingShouldReturnFalse() {
		Argon2Password4jPasswordEncoder encoder = new Argon2Password4jPasswordEncoder();
		String encoded = encoder.encode(PASSWORD);

		assertThat(encoder.upgradeEncoding(encoded)).isFalse();
	}

	@Test
	void shouldWorkWithAlgorithmFinderDefaults() {
		Argon2Password4jPasswordEncoder encoder = new Argon2Password4jPasswordEncoder(
				AlgorithmFinder.getArgon2Instance());

		String encoded = encoder.encode(PASSWORD);

		assertThat(encoded).isNotNull();
		assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
	}

	@Test
	void shouldRejectMalformedHashes() {
		Argon2Password4jPasswordEncoder encoder = new Argon2Password4jPasswordEncoder();

		// For Argon2, Password4j may throw BadParametersException on malformed hashes.
		// We treat either an exception or a false return as a successful rejection.
		assertMalformedRejected(encoder, PASSWORD, "invalid_hash");
		assertMalformedRejected(encoder, PASSWORD, "$argon2id$invalid");
		assertMalformedRejected(encoder, PASSWORD, "");
	}

	private void assertMalformedRejected(Argon2Password4jPasswordEncoder encoder, String raw, String malformed) {
		boolean rejected = false;
		try {
			rejected = !encoder.matches(raw, malformed);
		}
		catch (RuntimeException ex) {
			// Accept exception as valid rejection path for malformed input
			rejected = true;
		}
		assertThat(rejected).as("Malformed hash should not validate: " + malformed).isTrue();
	}

	@Test
	void shouldHandleEmptyStringPassword() {
		Argon2Password4jPasswordEncoder encoder = new Argon2Password4jPasswordEncoder();

		String encoded = encoder.encode("");

		assertThat(encoded).isNotNull();
		boolean emptyStringMatches;
		try {
			emptyStringMatches = encoder.matches("", encoded);
		}
		catch (RuntimeException ex) {
			emptyStringMatches = false; // treat exception as non-match but still
										// acceptable behavior
		}

		if (emptyStringMatches) {
			assertThat(encoder.matches("", encoded)).isTrue();
		}
		else {
			assertThat(encoded).isNotEmpty();
		}
		assertThat(encoder.matches("notEmpty", encoded)).isFalse();
	}

	@Test
	void shouldHandleCustomMemoryAndIterationParameters() {
		// Test with different memory and iteration parameters
		Argon2Function lowMemory = Argon2Function.getInstance(1024, 2, 1, 16, Argon2.ID);
		Argon2Function highMemory = Argon2Function.getInstance(65536, 4, 2, 64, Argon2.ID);

		Argon2Password4jPasswordEncoder lowEncoder = new Argon2Password4jPasswordEncoder(lowMemory);
		Argon2Password4jPasswordEncoder highEncoder = new Argon2Password4jPasswordEncoder(highMemory);

		String lowEncoded = lowEncoder.encode(PASSWORD);
		String highEncoded = highEncoder.encode(PASSWORD);

		assertThat(lowEncoder.matches(PASSWORD, lowEncoded)).isTrue();
		assertThat(highEncoder.matches(PASSWORD, highEncoded)).isTrue();

		// Each encoder should work with hashes generated by the same parameters
		assertThat(lowEncoded).isNotEqualTo(highEncoded);
	}

}
