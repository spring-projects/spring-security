/* Copyright 2004, 2005, 2006, 2007 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.acegisecurity.providers.encoding;

import junit.framework.TestCase;

public class Md4PasswordEncoderTests extends TestCase {

	public void testEncodeUnsaltedPassword() {
		Md4PasswordEncoder md4 = new Md4PasswordEncoder();
		md4.setEncodeHashAsBase64(true);
		String encodedPassword = md4.encodePassword("ww_uni123", null);
		assertEquals("8zobtq72iAt0W6KNqavGwg==", encodedPassword);
	}

	public void testEncodeSaltedPassword() {
		Md4PasswordEncoder md4 = new Md4PasswordEncoder();
		md4.setEncodeHashAsBase64(true);
		String encodedPassword = md4.encodePassword("ww_uni123", "Alan K Stewart");
		assertEquals("ZplT6P5Kv6Rlu6W4FIoYNA==", encodedPassword);
	}

	public void testEncodeNullPassword() {
		Md4PasswordEncoder md4 = new Md4PasswordEncoder();
		md4.setEncodeHashAsBase64(true);
		String encodedPassword = md4.encodePassword(null, null);
		assertEquals("MdbP4NFq6TG3PFnX4MCJwA==", encodedPassword);
	}

	public void testEncodeEmptyPassword() {
		Md4PasswordEncoder md4 = new Md4PasswordEncoder();
		md4.setEncodeHashAsBase64(true);
		String encodedPassword = md4.encodePassword("", null);
		assertEquals("MdbP4NFq6TG3PFnX4MCJwA==", encodedPassword);
	}

	public void testIsHexPasswordValid() {
		Md4PasswordEncoder md4 = new Md4PasswordEncoder();
		assertTrue(md4.isPasswordValid("31d6cfe0d16ae931b73c59d7e0c089c0", "", null));
	}

	public void testIsPasswordValid() {
		Md4PasswordEncoder md4 = new Md4PasswordEncoder();
		md4.setEncodeHashAsBase64(true);
		assertTrue(md4.isPasswordValid("8zobtq72iAt0W6KNqavGwg==", "ww_uni123", null));
	}

	public void testIsSaltedPasswordValid() {
		Md4PasswordEncoder md4 = new Md4PasswordEncoder();
		md4.setEncodeHashAsBase64(true);
		assertTrue(md4.isPasswordValid("ZplT6P5Kv6Rlu6W4FIoYNA==", "ww_uni123", "Alan K Stewart"));
	}
}
