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

import com.password4j.Argon2Function;
import com.password4j.BcryptFunction;
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
 * Password4j-based password encoders.
 *
 * @author Mehrdad Bozorgmehr
 */
class PasswordCompatibilityTests {

	private static final String PASSWORD = "password";

	// BCrypt Compatibility Tests
	@Test
	void bcryptEncodedWithSpringSecurityShouldMatchWithPassword4j() {
		BCryptPasswordEncoder springEncoder = new BCryptPasswordEncoder(10);
		BcryptPassword4jPasswordEncoder password4jEncoder = new BcryptPassword4jPasswordEncoder(
				BcryptFunction.getInstance(10));

		String encodedBySpring = springEncoder.encode(PASSWORD);
		boolean matchedByPassword4j = password4jEncoder.matches(PASSWORD, encodedBySpring);

		assertThat(matchedByPassword4j).isTrue();
	}

	@Test
	void bcryptEncodedWithPassword4jShouldMatchWithSpringSecurity() {
		BcryptPassword4jPasswordEncoder password4jEncoder = new BcryptPassword4jPasswordEncoder(
				BcryptFunction.getInstance(10));
		BCryptPasswordEncoder springEncoder = new BCryptPasswordEncoder(10);

		String encodedByPassword4j = password4jEncoder.encode(PASSWORD);
		boolean matchedBySpring = springEncoder.matches(PASSWORD, encodedByPassword4j);

		assertThat(matchedBySpring).isTrue();
	}

	// Argon2 Compatibility Tests
	@Test
	void argon2EncodedWithSpringSecurityShouldMatchWithPassword4j() {
		Argon2PasswordEncoder springEncoder = new Argon2PasswordEncoder(16, 32, 1, 4096, 3);
		Argon2Password4jPasswordEncoder password4jEncoder = new Argon2Password4jPasswordEncoder(
				Argon2Function.getInstance(4096, 3, 1, 32, Argon2.ID));

		String encodedBySpring = springEncoder.encode(PASSWORD);
		boolean matchedByPassword4j = password4jEncoder.matches(PASSWORD, encodedBySpring);

		assertThat(matchedByPassword4j).isTrue();
	}

	@Test
	void argon2EncodedWithPassword4jShouldMatchWithSpringSecurity() {
		Argon2Password4jPasswordEncoder password4jEncoder = new Argon2Password4jPasswordEncoder(
				Argon2Function.getInstance(4096, 3, 1, 32, Argon2.ID));
		Argon2PasswordEncoder springEncoder = new Argon2PasswordEncoder(16, 32, 1, 4096, 3);

		String encodedByPassword4j = password4jEncoder.encode(PASSWORD);
		boolean matchedBySpring = springEncoder.matches(PASSWORD, encodedByPassword4j);

		assertThat(matchedBySpring).isTrue();
	}

	// SCrypt Compatibility Tests
	@Test
	void scryptEncodedWithSpringSecurityShouldMatchWithPassword4j() {
		SCryptPasswordEncoder springEncoder = new SCryptPasswordEncoder(16384, 8, 1, 32, 64);
		ScryptPassword4jPasswordEncoder password4jEncoder = new ScryptPassword4jPasswordEncoder(
				ScryptFunction.getInstance(16384, 8, 1, 32));

		String encodedBySpring = springEncoder.encode(PASSWORD);
		boolean matchedByPassword4j = password4jEncoder.matches(PASSWORD, encodedBySpring);

		assertThat(matchedByPassword4j).isTrue();
	}

	@Test
	void scryptEncodedWithPassword4jShouldMatchWithSpringSecurity() {
		ScryptPassword4jPasswordEncoder password4jEncoder = new ScryptPassword4jPasswordEncoder(
				ScryptFunction.getInstance(16384, 8, 1, 32));
		SCryptPasswordEncoder springEncoder = new SCryptPasswordEncoder(16384, 8, 1, 32, 64);

		String encodedByPassword4j = password4jEncoder.encode(PASSWORD);
		boolean matchedBySpring = springEncoder.matches(PASSWORD, encodedByPassword4j);

		assertThat(matchedBySpring).isTrue();
	}

	// PBKDF2 Compatibility Tests
	@Test
	void pbkdf2EncodedWithSpringSecurityCannotMatchWithPassword4j() {
		// Note: Direct compatibility between Spring Security's Pbkdf2PasswordEncoder
		// and Password4j's PBKDF2 implementation is not possible because they use
		// different output formats. Spring Security uses hex encoding with a specific
		// format,
		// while our Password4jPasswordEncoder uses salt:hash format with Base64 encoding.
		Pbkdf2PasswordEncoder springEncoder = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8();
		Pbkdf2Password4jPasswordEncoder password4jEncoder = new Pbkdf2Password4jPasswordEncoder();

		String encodedBySpring = springEncoder.encode(PASSWORD);
		String encodedByPassword4j = password4jEncoder.encode(PASSWORD);

		// These should NOT match due to different formats
		// Spring Security will throw an exception when trying to decode Password4j
		// format,
		// which should be treated as a non-match
		boolean password4jCanMatchSpring = password4jEncoder.matches(PASSWORD, encodedBySpring);
		boolean springCanMatchPassword4j;
		try {
			springCanMatchPassword4j = springEncoder.matches(PASSWORD, encodedByPassword4j);
		}
		catch (IllegalArgumentException ex) {
			// Expected exception due to format incompatibility - treat as non-match
			springCanMatchPassword4j = false;
		}

		assertThat(password4jCanMatchSpring).isFalse();
		assertThat(springCanMatchPassword4j).isFalse();

		// But each should match its own encoding
		assertThat(springEncoder.matches(PASSWORD, encodedBySpring)).isTrue();
		assertThat(password4jEncoder.matches(PASSWORD, encodedByPassword4j)).isTrue();
	}

}
