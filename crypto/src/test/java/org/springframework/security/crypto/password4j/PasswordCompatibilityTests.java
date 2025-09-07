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
import com.password4j.BcryptFunction;
import com.password4j.CompressedPBKDF2Function;
import com.password4j.ScryptFunction;
import com.password4j.types.Argon2;
import org.junit.jupiter.api.Test;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests compatibility between existing Spring Security password encoders and
 * {@link Password4jPasswordEncoder}.
 *
 * @author Mehrdad Bozorgmehr
 */
class PasswordCompatibilityTests {

	private static final String PASSWORD = "password";

	// BCrypt Compatibility Tests
	@Test
	void bcryptEncodedWithSpringSecurityShouldMatchWithPassword4j() {
		BCryptPasswordEncoder springEncoder = new BCryptPasswordEncoder(10);
		Password4jPasswordEncoder password4jEncoder = new Password4jPasswordEncoder(BcryptFunction.getInstance(10));

		String encodedBySpring = springEncoder.encode(PASSWORD);
		boolean matchedByPassword4j = password4jEncoder.matches(PASSWORD, encodedBySpring);

		assertThat(matchedByPassword4j).isTrue();
	}

	@Test
	void bcryptEncodedWithPassword4jShouldMatchWithSpringSecurity() {
		BCryptPasswordEncoder springEncoder = new BCryptPasswordEncoder(10);
		Password4jPasswordEncoder password4jEncoder = new Password4jPasswordEncoder(BcryptFunction.getInstance(10));

		String encodedByPassword4j = password4jEncoder.encode(PASSWORD);
		boolean matchedBySpring = springEncoder.matches(PASSWORD, encodedByPassword4j);

		assertThat(matchedBySpring).isTrue();
	}

	// SCrypt Compatibility Tests
	@Test
	void scryptEncodedWithSpringSecurityShouldMatchWithPassword4j() {
		SCryptPasswordEncoder springEncoder = new SCryptPasswordEncoder(16384, 8, 1, 32, 64);
		Password4jPasswordEncoder password4jEncoder = new Password4jPasswordEncoder(
				ScryptFunction.getInstance(16384, 8, 1, 32));

		String encodedBySpring = springEncoder.encode(PASSWORD);
		boolean matchedByPassword4j = password4jEncoder.matches(PASSWORD, encodedBySpring);

		assertThat(matchedByPassword4j).isTrue();
	}

	@Test
	void scryptEncodedWithPassword4jShouldMatchWithSpringSecurity() {
		SCryptPasswordEncoder springEncoder = new SCryptPasswordEncoder(16384, 8, 1, 32, 64);
		Password4jPasswordEncoder password4jEncoder = new Password4jPasswordEncoder(
				ScryptFunction.getInstance(16384, 8, 1, 32));

		String encodedByPassword4j = password4jEncoder.encode(PASSWORD);
		boolean matchedBySpring = springEncoder.matches(PASSWORD, encodedByPassword4j);

		assertThat(matchedBySpring).isTrue();
	}

	// Argon2 Compatibility Tests
	@Test
	void argon2EncodedWithSpringSecurityShouldMatchWithPassword4j() {
		Argon2PasswordEncoder springEncoder = new Argon2PasswordEncoder(16, 32, 1, 65536, 3);
		Password4jPasswordEncoder password4jEncoder = new Password4jPasswordEncoder(
				Argon2Function.getInstance(65536, 3, 1, 32, Argon2.ID));

		String encodedBySpring = springEncoder.encode(PASSWORD);
		boolean matchedByPassword4j = password4jEncoder.matches(PASSWORD, encodedBySpring);

		assertThat(matchedByPassword4j).isTrue();
	}

	@Test
	void argon2EncodedWithPassword4jShouldMatchWithSpringSecurity() {
		Argon2PasswordEncoder springEncoder = new Argon2PasswordEncoder(16, 32, 1, 65536, 3);
		Password4jPasswordEncoder password4jEncoder = new Password4jPasswordEncoder(
				Argon2Function.getInstance(65536, 3, 1, 32, Argon2.ID));

		String encodedByPassword4j = password4jEncoder.encode(PASSWORD);
		boolean matchedBySpring = springEncoder.matches(PASSWORD, encodedByPassword4j);

		assertThat(matchedBySpring).isTrue();
	}

	// PBKDF2 Compatibility Tests - Note: Different format implementations
	@Test
	void pbkdf2BasicFunctionalityTest() {
		// Test that both encoders work independently with their own formats
		// Spring Security PBKDF2
		Pbkdf2PasswordEncoder springEncoder = new Pbkdf2PasswordEncoder("", 16, 100000,
				Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256);
		String springEncoded = springEncoder.encode(PASSWORD);
		assertThat(springEncoder.matches(PASSWORD, springEncoded)).isTrue();

		// Password4j PBKDF2
		Password4jPasswordEncoder password4jEncoder = new Password4jPasswordEncoder(
				CompressedPBKDF2Function.getInstance("SHA256", 100000, 32));
		String password4jEncoded = password4jEncoder.encode(PASSWORD);
		assertThat(password4jEncoder.matches(PASSWORD, password4jEncoded)).isTrue();

		// Note: These encoders use different hash formats and are not cross-compatible
		// This is expected behavior due to different implementation standards
	}

	// Cross-Algorithm Tests (should fail)
	@Test
	void bcryptEncodedPasswordShouldNotMatchArgon2Encoder() {
		Password4jPasswordEncoder bcryptEncoder = new Password4jPasswordEncoder(BcryptFunction.getInstance(10));
		Password4jPasswordEncoder argon2Encoder = new Password4jPasswordEncoder(AlgorithmFinder.getArgon2Instance());

		String bcryptEncoded = bcryptEncoder.encode(PASSWORD);
		boolean matchedByArgon2 = argon2Encoder.matches(PASSWORD, bcryptEncoded);

		assertThat(matchedByArgon2).isFalse();
	}

	@Test
	void argon2EncodedPasswordShouldNotMatchScryptEncoder() {
		Password4jPasswordEncoder argon2Encoder = new Password4jPasswordEncoder(AlgorithmFinder.getArgon2Instance());
		Password4jPasswordEncoder scryptEncoder = new Password4jPasswordEncoder(AlgorithmFinder.getScryptInstance());

		String argon2Encoded = argon2Encoder.encode(PASSWORD);
		boolean matchedByScrypt = scryptEncoder.matches(PASSWORD, argon2Encoded);

		assertThat(matchedByScrypt).isFalse();
	}

}
