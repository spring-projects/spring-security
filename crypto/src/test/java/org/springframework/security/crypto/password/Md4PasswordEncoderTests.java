/*
 * Copyright 2002-2017 the original author or authors.
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

package org.springframework.security.crypto.password;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@SuppressWarnings("deprecation")
public class Md4PasswordEncoderTests extends AbstractPasswordEncoderValidationTests {

	@BeforeEach
	void setup() {
		setEncoder(new Md4PasswordEncoder());
	}

	@Test
	public void matchesWhenEncodedPasswordNullThenFalse() {
		assertThat(getEncoder().matches("raw", null)).isFalse();
	}

	@Test
	public void matchesWhenEncodedPasswordEmptyThenFalse() {
		assertThat(getEncoder().matches("raw", "")).isFalse();
	}

	@Test
	public void testEncodeUnsaltedPassword() {
		Md4PasswordEncoder md4 = getEncoder();
		md4.setEncodeHashAsBase64(true);
		assertThat(md4.matches("ww_uni123", "8zobtq72iAt0W6KNqavGwg==")).isTrue();
	}

	@Test
	public void testEncodeSaltedPassword() {
		Md4PasswordEncoder md4 = getEncoder();
		md4.setEncodeHashAsBase64(true);
		assertThat(md4.matches("ww_uni123", "{Alan K Stewart}ZplT6P5Kv6Rlu6W4FIoYNA==")).isTrue();
	}

	@Test
	public void testNonAsciiPasswordHasCorrectHash() {
		assertThat(getEncoder().matches("\u4F60\u597d", "a7f1196539fd1f85f754ffd185b16e6e")).isTrue();
	}

	@Test
	public void testEncodedMatches() {
		String rawPassword = "password";
		String encodedPassword = getEncoder().encode(rawPassword);
		assertThat(getEncoder().matches(rawPassword, encodedPassword)).isTrue();
	}

	@Test
	public void javadocWhenHasSaltThenMatches() {
		assertThat(getEncoder().matches("password", "{thisissalt}6cc7924dad12ade79dfb99e424f25260"));
	}

}
