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
import com.password4j.HashingFunction;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link Password4jPasswordEncoder}.
 *
 * @author Mehrdad Bozorgmehr
 */
class Password4jPasswordEncoderTests {

	private static final String PASSWORD = "password";

	private static final String WRONG_PASSWORD = "wrongpassword";

	// Constructor Tests
	@Test
	void constructorWithNullHashingFunctionShouldThrowException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new Password4jPasswordEncoder(null))
			.withMessage("hashingFunction cannot be null");
	}

	@Test
	void constructorWithValidHashingFunctionShouldWork() {
		HashingFunction hashingFunction = BcryptFunction.getInstance(10);
		Password4jPasswordEncoder encoder = new Password4jPasswordEncoder(hashingFunction);
		assertThat(encoder).isNotNull();
	}

	// Basic functionality tests with real HashingFunction instances
	@Test
	void encodeShouldReturnNonNullHashedPassword() {
		HashingFunction hashingFunction = BcryptFunction.getInstance(4); // Use low cost
		// for faster
		// tests
		Password4jPasswordEncoder encoder = new Password4jPasswordEncoder(hashingFunction);

		String result = encoder.encode(PASSWORD);

		assertThat(result).isNotNull().isNotEqualTo(PASSWORD);
	}

	@Test
	void matchesShouldReturnTrueForValidPassword() {
		HashingFunction hashingFunction = BcryptFunction.getInstance(4); // Use low cost
		// for faster
		// tests
		Password4jPasswordEncoder encoder = new Password4jPasswordEncoder(hashingFunction);

		String encoded = encoder.encode(PASSWORD);
		boolean result = encoder.matches(PASSWORD, encoded);

		assertThat(result).isTrue();
	}

	@Test
	void matchesShouldReturnFalseForInvalidPassword() {
		HashingFunction hashingFunction = BcryptFunction.getInstance(4); // Use low cost
		// for faster
		// tests
		Password4jPasswordEncoder encoder = new Password4jPasswordEncoder(hashingFunction);

		String encoded = encoder.encode(PASSWORD);
		boolean result = encoder.matches(WRONG_PASSWORD, encoded);

		assertThat(result).isFalse();
	}

	@Test
	void matchesShouldReturnFalseForMalformedHash() {
		HashingFunction hashingFunction = BcryptFunction.getInstance(4);
		Password4jPasswordEncoder encoder = new Password4jPasswordEncoder(hashingFunction);

		// Test with malformed hash that should cause Password4j to throw an exception
		boolean result = encoder.matches(PASSWORD, "invalid-hash-format");

		assertThat(result).isFalse();
	}

	@Test
	void upgradeEncodingShouldReturnFalse() {
		HashingFunction hashingFunction = BcryptFunction.getInstance(4);
		Password4jPasswordEncoder encoder = new Password4jPasswordEncoder(hashingFunction);

		String encoded = encoder.encode(PASSWORD);
		boolean result = encoder.upgradeEncoding(encoded);

		assertThat(result).isFalse();
	}

	// AlgorithmFinder Sanity Check Tests
	@Test
	void algorithmFinderBcryptSanityCheck() {
		Password4jPasswordEncoder encoder = new Password4jPasswordEncoder(AlgorithmFinder.getBcryptInstance());

		String encoded = encoder.encode(PASSWORD);
		assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
		assertThat(encoder.matches(WRONG_PASSWORD, encoded)).isFalse();
	}

	@Test
	void algorithmFinderArgon2SanityCheck() {
		Password4jPasswordEncoder encoder = new Password4jPasswordEncoder(AlgorithmFinder.getArgon2Instance());

		String encoded = encoder.encode(PASSWORD);
		assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
		assertThat(encoder.matches(WRONG_PASSWORD, encoded)).isFalse();
	}

	@Test
	void algorithmFinderScryptSanityCheck() {
		Password4jPasswordEncoder encoder = new Password4jPasswordEncoder(AlgorithmFinder.getScryptInstance());

		String encoded = encoder.encode(PASSWORD);
		assertThat(encoder.matches(PASSWORD, encoded)).isTrue();
		assertThat(encoder.matches(WRONG_PASSWORD, encoded)).isFalse();
	}

}
