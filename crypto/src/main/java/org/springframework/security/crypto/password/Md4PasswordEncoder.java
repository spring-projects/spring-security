/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.crypto.password;

import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;

import java.security.MessageDigest;
import java.util.Base64;

/**
 * This {@link PasswordEncoder} is provided for legacy purposes only and is not considered secure.
 *
 * Encodes passwords using MD4.
 *
 * @author Ray Krueger
 * @author Luke Taylor
 * @since 1.0.1
 * @deprecated Digest based password encoding is not considered secure. Instead use an
 * adaptive one way funciton like BCryptPasswordEncoder, Pbkdf2PasswordEncoder, or
 * SCryptPasswordEncoder. Even better use {@link DelegatingPasswordEncoder} which supports
 * password upgrades.
 */
@Deprecated
public class Md4PasswordEncoder implements PasswordEncoder {
	private static final String PREFIX = "{";
	private static final String SUFFIX = "}";
	private StringKeyGenerator saltGenerator = new Base64StringKeyGenerator();
	private boolean encodeHashAsBase64;

	private Digester digester;


	public void setEncodeHashAsBase64(boolean encodeHashAsBase64) {
		this.encodeHashAsBase64 = encodeHashAsBase64;
	}

	/**
	 * Encodes the rawPass using a MessageDigest. If a salt is specified it will be merged
	 * with the password before encoding.
	 *
	 * @param rawPassword The plain text password
	 * @return Hex string of password digest (or base64 encoded string if
	 * encodeHashAsBase64 is enabled.
	 */
	public String encode(CharSequence rawPassword) {
		String salt = PREFIX + this.saltGenerator.generateKey() + SUFFIX;
		return digest(salt, rawPassword);
	}

	private String digest(String salt, CharSequence rawPassword) {
		if(rawPassword == null) {
			rawPassword = "";
		}
		String saltedPassword = rawPassword + salt;
		byte[] saltedPasswordBytes = Utf8.encode(saltedPassword);

		Md4 md4 = new Md4();
		md4.update(saltedPasswordBytes, 0, saltedPasswordBytes.length);

		byte[] digest = md4.digest();
		String encoded = encode(digest);
		return salt + encoded;
	}

	private String encode(byte[] digest) {
		if (this.encodeHashAsBase64) {
			return Utf8.decode(Base64.getEncoder().encode(digest));
		}
		else {
			return new String(Hex.encode(digest));
		}
	}

	/**
	 * Takes a previously encoded password and compares it with a rawpassword after mixing
	 * in the salt and encoding that value
	 *
	 * @param rawPassword plain text password
	 * @param encodedPassword previously encoded password
	 * @return true or false
	 */
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		String salt = extractSalt(encodedPassword);
		String rawPasswordEncoded = digest(salt, rawPassword);
		return PasswordEncoderUtils.equals(encodedPassword.toString(), rawPasswordEncoded);
	}

	private String extractSalt(String prefixEncodedPassword) {
		int start = prefixEncodedPassword.indexOf(PREFIX);
		if(start != 0) {
			return "";
		}
		int end = prefixEncodedPassword.indexOf(SUFFIX, start);
		if(end < 0) {
			return "";
		}
		return prefixEncodedPassword.substring(start, end + 1);
	}
}
