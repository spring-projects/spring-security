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


import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;


public class Md4PasswordEncoderTests {

	@Test
	public void testEncodeUnsaltedPassword() {
		Md4PasswordEncoder md4 = new Md4PasswordEncoder();
		md4.setEncodeHashAsBase64(true);
		assertThat(md4.matches("ww_uni123", "8zobtq72iAt0W6KNqavGwg==")).isTrue();
	}

	@Test
	public void testEncodeSaltedPassword() {
		Md4PasswordEncoder md4 = new Md4PasswordEncoder();
		md4.setEncodeHashAsBase64(true);
		assertThat(md4.matches("ww_uni123", "{Alan K Stewart}ZplT6P5Kv6Rlu6W4FIoYNA==")).isTrue();
	}

	@Test
	public void testEncodeNullPassword() {
		Md4PasswordEncoder md4 = new Md4PasswordEncoder();
		md4.setEncodeHashAsBase64(true);
		assertThat(md4.matches(null, "MdbP4NFq6TG3PFnX4MCJwA==")).isTrue();
	}

	@Test
	public void testEncodeEmptyPassword() {
		Md4PasswordEncoder md4 = new Md4PasswordEncoder();
		md4.setEncodeHashAsBase64(true);
		assertThat(md4.matches(null, "MdbP4NFq6TG3PFnX4MCJwA==")).isTrue();
	}

	@Test
	public void testNonAsciiPasswordHasCorrectHash() {
		Md4PasswordEncoder md4 = new Md4PasswordEncoder();
		assertThat(md4.matches("\u4F60\u597d", "a7f1196539fd1f85f754ffd185b16e6e")).isTrue();
	}

	@Test
	public void testEncodedMatches() {
		String rawPassword = "password";
		Md4PasswordEncoder md4 = new Md4PasswordEncoder();
		String encodedPassword = md4.encode(rawPassword);

		assertThat(md4.matches(rawPassword, encodedPassword)).isTrue();
	}

	@Test
	public void javadocWhenHasSaltThenMatches() {
		Md4PasswordEncoder encoder = new Md4PasswordEncoder();
		assertThat(encoder.matches("password", "{thisissalt}6cc7924dad12ade79dfb99e424f25260"));
	}
}

