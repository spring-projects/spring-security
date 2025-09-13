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

import com.password4j.BcryptFunction;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Base functionality tests for {@link Password4jPasswordEncoder} implementations. These
 * tests verify the common behavior across all concrete password encoder subclasses.
 *
 * @author Mehrdad Bozorgmehr
 */
class Password4jPasswordEncoderTests {

	private static final String PASSWORD = "password";

	private static final String WRONG_PASSWORD = "wrongpassword";

	// Test abstract class behavior through concrete implementation
	@Test
	void encodeShouldReturnNonNullHashedPassword() {
		BcryptPassword4jPasswordEncoder encoder = new BcryptPassword4jPasswordEncoder(BcryptFunction.getInstance(4));

		String result = encoder.encode(PASSWORD);

		assertThat(result).isNotNull().isNotEqualTo(PASSWORD);
	}

	@Test
	void matchesShouldReturnTrueForValidPassword() {
		BcryptPassword4jPasswordEncoder encoder = new BcryptPassword4jPasswordEncoder(BcryptFunction.getInstance(4));

		String encoded = encoder.encode(PASSWORD);
		boolean result = encoder.matches(PASSWORD, encoded);

		assertThat(result).isTrue();
	}

	@Test
	void matchesShouldReturnFalseForInvalidPassword() {
		BcryptPassword4jPasswordEncoder encoder = new BcryptPassword4jPasswordEncoder(BcryptFunction.getInstance(4));

		String encoded = encoder.encode(PASSWORD);
		boolean result = encoder.matches(WRONG_PASSWORD, encoded);

		assertThat(result).isFalse();
	}

	@Test
	void encodeNullPasswordShouldReturnNull() {
		BcryptPassword4jPasswordEncoder encoder = new BcryptPassword4jPasswordEncoder(BcryptFunction.getInstance(4));

		assertThat(encoder.encode(null)).isNull();
	}

	@Test
	void multipleEncodesProduceDifferentHashesButAllMatch() {
		BcryptPassword4jPasswordEncoder encoder = new BcryptPassword4jPasswordEncoder(BcryptFunction.getInstance(4));

		String encoded1 = encoder.encode(PASSWORD);
		String encoded2 = encoder.encode(PASSWORD);
		// Bcrypt should produce different salted hashes for the same raw password
		assertThat(encoded1).isNotEqualTo(encoded2);
		assertThat(encoder.matches(PASSWORD, encoded1)).isTrue();
		assertThat(encoder.matches(PASSWORD, encoded2)).isTrue();
	}

	@Test
	void upgradeEncodingShouldReturnFalse() {
		BcryptPassword4jPasswordEncoder encoder = new BcryptPassword4jPasswordEncoder(BcryptFunction.getInstance(4));

		String encoded = encoder.encode(PASSWORD);
		boolean result = encoder.upgradeEncoding(encoded);

		assertThat(result).isFalse();
	}

	@Test
	void matchesShouldReturnFalseWhenRawOrEncodedNullOrEmpty() {
		BcryptPassword4jPasswordEncoder encoder = new BcryptPassword4jPasswordEncoder(BcryptFunction.getInstance(4));
		String encoded = encoder.encode(PASSWORD);
		assertThat(encoder.matches(null, encoded)).isFalse();
		assertThat(encoder.matches("", encoded)).isFalse();
		assertThat(encoder.matches(PASSWORD, null)).isFalse();
		assertThat(encoder.matches(PASSWORD, "")).isFalse();
	}

}
