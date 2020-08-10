/*
 * Copyright 2002-2018 the original author or authors.
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

import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;

import java.security.MessageDigest;
import java.util.Base64;

/**
 * This {@link PasswordEncoder} is provided for legacy purposes only and is not considered
 * secure.
 *
 * Encodes passwords using the passed in {@link MessageDigest}.
 *
 * The general format of the password is:
 *
 * <pre>
 * s = salt == null ? "" : "{" + salt + "}"
 * s + digest(password + s)
 * </pre>
 *
 * Such that "salt" is the salt, digest is the digest method, and password is the actual
 * password. For example when using MD5, a password of "password", and a salt of
 * "thisissalt":
 *
 * <pre>
 * String s = salt == null ? "" : "{" + salt + "}";
 * s + md5(password + s)
 * "{thisissalt}" + md5(password + "{thisissalt}")
 * "{thisissalt}2a4e7104c2780098f50ed5a84bb2323d"
 * </pre>
 *
 * If the salt does not exist, then omit "{salt}" like this:
 *
 * <pre>
 * digest(password)
 * </pre>
 *
 * If the salt is an empty String, then only use "{}" like this:
 *
 * <pre>
 * "{}" + digest(password + "{}")
 * </pre>
 *
 * The format is intended to work with the DigestPasswordEncoder that was found in the
 * Spring Security core module. However, the passwords will need to be migrated to include
 * any salt with the password since this API provides Salt internally vs making it the
 * responsibility of the user. To migrate passwords from the SaltSource use the following:
 *
 * <pre>
 * String salt = saltSource.getSalt(user);
 * String s = salt == null ? null : "{" + salt + "}";
 * String migratedPassword = s + user.getPassword();
 * </pre>
 *
 * @author Ray Krueger
 * @author Luke Taylor
 * @author Rob Winch
 * @since 5.0
 * @deprecated Digest based password encoding is not considered secure. Instead use an
 * adaptive one way function like BCryptPasswordEncoder, Pbkdf2PasswordEncoder, or
 * SCryptPasswordEncoder. Even better use {@link DelegatingPasswordEncoder} which supports
 * password upgrades. There are no plans to remove this support. It is deprecated to
 * indicate that this is a legacy implementation and using it is considered insecure.
 */
@Deprecated
public class MessageDigestPasswordEncoder implements PasswordEncoder {

	private static final String PREFIX = "{";

	private static final String SUFFIX = "}";

	private StringKeyGenerator saltGenerator = new Base64StringKeyGenerator();

	private boolean encodeHashAsBase64;

	private Digester digester;

	/**
	 * The digest algorithm to use Supports the named
	 * <a href="https://java.sun.com/j2se/1.4.2/docs/guide/security/CryptoSpec.html#AppA">
	 * Message Digest Algorithms</a> in the Java environment.
	 * @param algorithm
	 */
	public MessageDigestPasswordEncoder(String algorithm) {
		this.digester = new Digester(algorithm, 1);
	}

	public void setEncodeHashAsBase64(boolean encodeHashAsBase64) {
		this.encodeHashAsBase64 = encodeHashAsBase64;
	}

	/**
	 * Encodes the rawPass using a MessageDigest. If a salt is specified it will be merged
	 * with the password before encoding.
	 * @param rawPassword The plain text password
	 * @return Hex string of password digest (or base64 encoded string if
	 * encodeHashAsBase64 is enabled.
	 */
	public String encode(CharSequence rawPassword) {
		String salt = PREFIX + this.saltGenerator.generateKey() + SUFFIX;
		return digest(salt, rawPassword);
	}

	private String digest(String salt, CharSequence rawPassword) {
		String saltedPassword = rawPassword + salt;

		byte[] digest = this.digester.digest(Utf8.encode(saltedPassword));
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
	 * @param rawPassword plain text password
	 * @param encodedPassword previously encoded password
	 * @return true or false
	 */
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		String salt = extractSalt(encodedPassword);
		String rawPasswordEncoded = digest(salt, rawPassword);
		return PasswordEncoderUtils.equals(encodedPassword.toString(), rawPasswordEncoded);
	}

	/**
	 * Sets the number of iterations for which the calculated hash value should be
	 * "stretched". If this is greater than one, the initial digest is calculated, the
	 * digest function will be called repeatedly on the result for the additional number
	 * of iterations.
	 * @param iterations the number of iterations which will be executed on the hashed
	 * password/salt value. Defaults to 1.
	 */
	public void setIterations(int iterations) {
		this.digester.setIterations(iterations);
	}

	private String extractSalt(String prefixEncodedPassword) {
		int start = prefixEncodedPassword.indexOf(PREFIX);
		if (start != 0) {
			return "";
		}
		int end = prefixEncodedPassword.indexOf(SUFFIX, start);
		if (end < 0) {
			return "";
		}
		return prefixEncodedPassword.substring(start, end + 1);
	}

}
