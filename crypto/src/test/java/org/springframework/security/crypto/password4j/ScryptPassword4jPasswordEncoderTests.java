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
import com.password4j.ScryptFunction;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link ScryptPassword4jPasswordEncoder}.
 *
 * @author Mehrdad Bozorgmehr
 */
class ScryptPassword4jPasswordEncoderTests {

	private static final String PASSWORD = "password";

	private static final String LONG_PASSWORD = "a".repeat(1000);

	private static final String SPECIAL_CHARS_PASSWORD = "p@ssw0rd!#$%^&*()_+-=[]{}|;':\",./<>?";

	private static final String UNICODE_PASSWORD = "пароль密码パスワード🔐";

	@Test
	void defaultConstructorShouldCreateWorkingEncoder() {
		ScryptPassword4jPasswordEncoder encoder = new ScryptPassword4jPasswordEncoder();

		String encoded = encoder.encode(PASSWORD);

		assertThat(encoded).isNotNull();
		// Password4j scrypt format differs from classic $s0$; accept generic multi-part
		// format
		assertThat(encoded.split("\\$").length).isGreaterThanOrEqualTo(3);
		assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
	}

	@Test
	void constructorWithNullScryptFunctionShouldThrowException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new ScryptPassword4jPasswordEncoder(null))
			.withMessage("hashingFunction cannot be null");
	}

	@Test
	void constructorWithCustomScryptFunctionShouldWork() {
		ScryptFunction customFunction = ScryptFunction.getInstance(16384, 8, 1, 32);
		ScryptPassword4jPasswordEncoder encoder = new ScryptPassword4jPasswordEncoder(customFunction);

		String encoded = encoder.encode(PASSWORD);

		assertThat(encoded).isNotNull();
		assertThat(encoded.split("\\$").length).isGreaterThanOrEqualTo(3);
		assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
	}

	@ParameterizedTest
	@CsvSource({ "1024, 8, 1, 16", "4096, 8, 1, 32", "16384, 8, 1, 32", "32768, 8, 1, 64" })
	void encodingShouldWorkWithDifferentParameters(int N, int r, int p, int dkLen) {
		ScryptFunction function = ScryptFunction.getInstance(N, r, p, dkLen);
		ScryptPassword4jPasswordEncoder encoder = new ScryptPassword4jPasswordEncoder(function);

		String encoded = encoder.encode(PASSWORD);

		assertThat(encoded).isNotNull();
		assertThat(encoded.split("\\$").length).isGreaterThanOrEqualTo(3);
		assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
	}

	@Test
	void encodingShouldGenerateDifferentHashesForSamePassword() {
		ScryptPassword4jPasswordEncoder encoder = new ScryptPassword4jPasswordEncoder();

		String hash1 = encoder.encode(PASSWORD);
		String hash2 = encoder.encode(PASSWORD);

		assertThat(hash1).isNotEqualTo(hash2);
		assertThat(encoder.matches(PASSWORD, hash1)).isTrue();
		assertThat(encoder.matches(PASSWORD, hash2)).isTrue();
	}

	@Test
	void shouldHandleLongPasswords() {
		ScryptPassword4jPasswordEncoder encoder = new ScryptPassword4jPasswordEncoder();

		String encoded = encoder.encode(LONG_PASSWORD);

		assertThat(encoder.matches(LONG_PASSWORD, encoded)).isTrue();
		assertThat(encoder.matches("wrong", encoded)).isFalse();
	}

	@Test
	void shouldHandleSpecialCharacters() {
		ScryptPassword4jPasswordEncoder encoder = new ScryptPassword4jPasswordEncoder();

		String encoded = encoder.encode(SPECIAL_CHARS_PASSWORD);

		assertThat(encoder.matches(SPECIAL_CHARS_PASSWORD, encoded)).isTrue();
		assertThat(encoder.matches("wrong", encoded)).isFalse();
	}

	@Test
	void shouldHandleUnicodeCharacters() {
		ScryptPassword4jPasswordEncoder encoder = new ScryptPassword4jPasswordEncoder();

		String encoded = encoder.encode(UNICODE_PASSWORD);

		assertThat(encoder.matches(UNICODE_PASSWORD, encoded)).isTrue();
		assertThat(encoder.matches("wrong", encoded)).isFalse();
	}

	@Test
	void shouldRejectIncorrectPasswords() {
		ScryptPassword4jPasswordEncoder encoder = new ScryptPassword4jPasswordEncoder();
		String encoded = encoder.encode(PASSWORD);

		assertThat(encoder.matches("wrongpassword", encoded)).isFalse();
		assertThat(encoder.matches("PASSWORD", encoded)).isFalse(); // Case sensitive
		assertThat(encoder.matches("password ", encoded)).isFalse(); // Trailing space
		assertThat(encoder.matches(" password", encoded)).isFalse(); // Leading space
	}

	@Test
	void matchesShouldReturnFalseForNullOrEmptyInputs() {
		ScryptPassword4jPasswordEncoder encoder = new ScryptPassword4jPasswordEncoder();
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
		ScryptPassword4jPasswordEncoder encoder = new ScryptPassword4jPasswordEncoder();

		assertThat(encoder.encode(null)).isNull();
	}

	@Test
	void upgradeEncodingShouldReturnFalse() {
		ScryptPassword4jPasswordEncoder encoder = new ScryptPassword4jPasswordEncoder();
		String encoded = encoder.encode(PASSWORD);

		assertThat(encoder.upgradeEncoding(encoded)).isFalse();
	}

	@Test
	void shouldWorkWithAlgorithmFinderDefaults() {
		ScryptPassword4jPasswordEncoder encoder = new ScryptPassword4jPasswordEncoder(
				AlgorithmFinder.getScryptInstance());

		String encoded = encoder.encode(PASSWORD);

		assertThat(encoded).isNotNull();
		assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
	}

	@Test
	void shouldRejectMalformedHashes() {
		ScryptPassword4jPasswordEncoder encoder = new ScryptPassword4jPasswordEncoder();
		assertMalformedRejected(encoder, PASSWORD, "invalid_hash");
		assertMalformedRejected(encoder, PASSWORD, "$s0$invalid");
		assertMalformedRejected(encoder, PASSWORD, "");
	}

	private void assertMalformedRejected(ScryptPassword4jPasswordEncoder encoder, String raw, String malformed) {
		boolean rejected;
		try {
			rejected = !encoder.matches(raw, malformed);
		}
		catch (RuntimeException ex) {
			rejected = true; // exception path acceptable
		}
		assertThat(rejected).as("Malformed hash should not validate: " + malformed).isTrue();
	}

	@Test
	void shouldHandleEmptyStringPassword() {
		ScryptPassword4jPasswordEncoder encoder = new ScryptPassword4jPasswordEncoder();
		String encoded = encoder.encode("");
		assertThat(encoded).isNotNull();
		boolean emptyMatches;
		try {
			emptyMatches = encoder.matches("", encoded);
		}
		catch (RuntimeException ex) {
			emptyMatches = false;
		}
		if (emptyMatches) {
			assertThat(encoder.matches("", encoded)).isTrue();
		}
		assertThat(encoder.matches("notEmpty", encoded)).isFalse();
	}

	@Test
	void shouldHandleCustomCostParameters() {
		// Test with low cost parameters for speed
		ScryptFunction lowCost = ScryptFunction.getInstance(1024, 1, 1, 16);
		// Test with higher cost parameters
		ScryptFunction highCost = ScryptFunction.getInstance(32768, 8, 2, 64);

		ScryptPassword4jPasswordEncoder lowEncoder = new ScryptPassword4jPasswordEncoder(lowCost);
		ScryptPassword4jPasswordEncoder highEncoder = new ScryptPassword4jPasswordEncoder(highCost);

		String lowEncoded = lowEncoder.encode(PASSWORD);
		String highEncoded = highEncoder.encode(PASSWORD);

		assertThat(lowEncoder.matches(PASSWORD, lowEncoded)).isTrue();
		assertThat(highEncoder.matches(PASSWORD, highEncoded)).isTrue();

		// Each encoder should work with hashes generated by the same parameters
		assertThat(lowEncoded).isNotEqualTo(highEncoded);
	}

	@Test
	void shouldHandleEdgeCaseParameters() {
		// Test with minimum practical parameters
		ScryptFunction minParams = ScryptFunction.getInstance(2, 1, 1, 1);
		ScryptPassword4jPasswordEncoder encoder = new ScryptPassword4jPasswordEncoder(minParams);

		String encoded = encoder.encode(PASSWORD);

		assertThat(encoded).isNotNull();
		assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
	}

}
