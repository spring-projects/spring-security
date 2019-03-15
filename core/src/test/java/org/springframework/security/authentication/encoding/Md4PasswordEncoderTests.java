/*
 * Copyright 2004, 2005, 2006, 2007 Acegi Technology Pty Limited
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

package org.springframework.security.authentication.encoding;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;

public class Md4PasswordEncoderTests {

	@Test
	public void testEncodeUnsaltedPassword() {
		Md4PasswordEncoder md4 = new Md4PasswordEncoder();
		md4.setEncodeHashAsBase64(true);
		String encodedPassword = md4.encodePassword("ww_uni123", null);
		assertThat(encodedPassword).isEqualTo("8zobtq72iAt0W6KNqavGwg==");
	}

	@Test
	public void testEncodeSaltedPassword() {
		Md4PasswordEncoder md4 = new Md4PasswordEncoder();
		md4.setEncodeHashAsBase64(true);
		String encodedPassword = md4.encodePassword("ww_uni123", "Alan K Stewart");
		assertThat(encodedPassword).isEqualTo("ZplT6P5Kv6Rlu6W4FIoYNA==");
	}

	@Test
	public void testEncodeNullPassword() {
		Md4PasswordEncoder md4 = new Md4PasswordEncoder();
		md4.setEncodeHashAsBase64(true);
		String encodedPassword = md4.encodePassword(null, null);
		assertThat(encodedPassword).isEqualTo("MdbP4NFq6TG3PFnX4MCJwA==");
	}

	@Test
	public void testEncodeEmptyPassword() {
		Md4PasswordEncoder md4 = new Md4PasswordEncoder();
		md4.setEncodeHashAsBase64(true);
		String encodedPassword = md4.encodePassword("", null);
		assertThat(encodedPassword).isEqualTo("MdbP4NFq6TG3PFnX4MCJwA==");
	}

	@Test
	public void testNonAsciiPasswordHasCorrectHash() {
		Md4PasswordEncoder md4 = new Md4PasswordEncoder();
		String encodedPassword = md4.encodePassword("\u4F60\u597d", null);
		assertThat(encodedPassword).isEqualTo("a7f1196539fd1f85f754ffd185b16e6e");
	}

	@Test
	public void testIsHexPasswordValid() {
		Md4PasswordEncoder md4 = new Md4PasswordEncoder();
		assertThat(md4.isPasswordValid("31d6cfe0d16ae931b73c59d7e0c089c0", "",
				null)).isTrue();
	}

	@Test
	public void testIsPasswordValid() {
		Md4PasswordEncoder md4 = new Md4PasswordEncoder();
		md4.setEncodeHashAsBase64(true);
		assertThat(md4.isPasswordValid("8zobtq72iAt0W6KNqavGwg==", "ww_uni123",
				null)).isTrue();
	}

	@Test
	public void testIsSaltedPasswordValid() {
		Md4PasswordEncoder md4 = new Md4PasswordEncoder();
		md4.setEncodeHashAsBase64(true);
		assertThat(md4.isPasswordValid("ZplT6P5Kv6Rlu6W4FIoYNA==", "ww_uni123",
				"Alan K Stewart")).isTrue();
	}
}
