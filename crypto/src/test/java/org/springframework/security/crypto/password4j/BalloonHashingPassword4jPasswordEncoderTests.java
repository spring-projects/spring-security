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
import com.password4j.BalloonHashingFunction;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link BalloonHashingPassword4jPasswordEncoder}.
 *
 * @author Mehrdad Bozorgmehr
 */
class BalloonHashingPassword4jPasswordEncoderTests {

	private static final String PASSWORD = "password";

	private static final String DIFFERENT_PASSWORD = "differentpassword";

	@Test
	void constructorWithNullFunctionShouldThrowException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new BalloonHashingPassword4jPasswordEncoder(null))
			.withMessage("balloonHashingFunction cannot be null");
	}

	@Test
	void constructorWithInvalidSaltLengthShouldThrowException() {
		BalloonHashingFunction function = AlgorithmFinder.getBalloonHashingInstance();
		assertThatIllegalArgumentException().isThrownBy(() -> new BalloonHashingPassword4jPasswordEncoder(function, 0))
			.withMessage("saltLength must be positive");
		assertThatIllegalArgumentException().isThrownBy(() -> new BalloonHashingPassword4jPasswordEncoder(function, -1))
			.withMessage("saltLength must be positive");
	}

	@Test
	void defaultConstructorShouldWork() {
		BalloonHashingPassword4jPasswordEncoder encoder = new BalloonHashingPassword4jPasswordEncoder();

		String encoded = encoder.encode(PASSWORD);

		assertThat(encoded).isNotNull().isNotEqualTo(PASSWORD);
		assertThat(encoded).contains(":");
		assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
	}

	@Test
	void customFunctionConstructorShouldWork() {
		BalloonHashingFunction customFunction = BalloonHashingFunction.getInstance("SHA-256", 512, 2, 3);
		BalloonHashingPassword4jPasswordEncoder encoder = new BalloonHashingPassword4jPasswordEncoder(customFunction);

		String encoded = encoder.encode(PASSWORD);

		assertThat(encoded).isNotNull().isNotEqualTo(PASSWORD);
		assertThat(encoded).contains(":");
		assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
	}

	@Test
	void customSaltLengthConstructorShouldWork() {
		BalloonHashingFunction function = AlgorithmFinder.getBalloonHashingInstance();
		BalloonHashingPassword4jPasswordEncoder encoder = new BalloonHashingPassword4jPasswordEncoder(function, 16);

		String encoded = encoder.encode(PASSWORD);

		assertThat(encoded).isNotNull().isNotEqualTo(PASSWORD);
		assertThat(encoded).contains(":");
		assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
	}

	@Test
	void encodeShouldIncludeSaltInOutput() {
		BalloonHashingPassword4jPasswordEncoder encoder = new BalloonHashingPassword4jPasswordEncoder();

		String encoded = encoder.encode(PASSWORD);

		assertThat(encoded).contains(":");
		String[] parts = encoded.split(":");
		assertThat(parts).hasSize(2);
		assertThat(parts[0]).isNotEmpty(); // salt part
		assertThat(parts[1]).isNotEmpty(); // hash part
	}

	@Test
	void matchesShouldReturnTrueForCorrectPassword() {
		BalloonHashingPassword4jPasswordEncoder encoder = new BalloonHashingPassword4jPasswordEncoder();

		String encoded = encoder.encode(PASSWORD);
		boolean matches = encoder.matches(PASSWORD, encoded);

		assertThat(matches).isTrue();
	}

	@Test
	void matchesShouldReturnFalseForIncorrectPassword() {
		BalloonHashingPassword4jPasswordEncoder encoder = new BalloonHashingPassword4jPasswordEncoder();

		String encoded = encoder.encode(PASSWORD);
		boolean matches = encoder.matches(DIFFERENT_PASSWORD, encoded);

		assertThat(matches).isFalse();
	}

	@Test
	void matchesShouldReturnFalseForMalformedEncodedPassword() {
		BalloonHashingPassword4jPasswordEncoder encoder = new BalloonHashingPassword4jPasswordEncoder();

		assertThat(encoder.matches(PASSWORD, "malformed")).isFalse();
		assertThat(encoder.matches(PASSWORD, "no:delimiter:in:wrong:places")).isFalse();
		assertThat(encoder.matches(PASSWORD, "invalid_base64!:hash")).isFalse();
	}

	@Test
	void multipleEncodingsShouldProduceDifferentHashesButAllMatch() {
		BalloonHashingPassword4jPasswordEncoder encoder = new BalloonHashingPassword4jPasswordEncoder();

		String encoded1 = encoder.encode(PASSWORD);
		String encoded2 = encoder.encode(PASSWORD);

		assertThat(encoded1).isNotEqualTo(encoded2); // Different salts should produce
														// different results
		assertThat(encoder.matches(PASSWORD, encoded1)).isTrue();
		assertThat(encoder.matches(PASSWORD, encoded2)).isTrue();
	}

	@Test
	void upgradeEncodingShouldReturnFalse() {
		BalloonHashingPassword4jPasswordEncoder encoder = new BalloonHashingPassword4jPasswordEncoder();

		String encoded = encoder.encode(PASSWORD);
		boolean shouldUpgrade = encoder.upgradeEncoding(encoded);

		assertThat(shouldUpgrade).isFalse();
	}

	@Test
	void encodeNullShouldReturnNull() {
		BalloonHashingPassword4jPasswordEncoder encoder = new BalloonHashingPassword4jPasswordEncoder();

		assertThat(encoder.encode(null)).isNull();
	}

	@Test
	void matchesWithNullOrEmptyValuesShouldReturnFalse() {
		BalloonHashingPassword4jPasswordEncoder encoder = new BalloonHashingPassword4jPasswordEncoder();
		String encoded = encoder.encode(PASSWORD);

		assertThat(encoder.matches(null, encoded)).isFalse();
		assertThat(encoder.matches("", encoded)).isFalse();
		assertThat(encoder.matches(PASSWORD, null)).isFalse();
		assertThat(encoder.matches(PASSWORD, "")).isFalse();
	}

}
