/*
 * Copyright 2011-2017 the original author or authors.
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
package org.springframework.security.crypto.pbkdf2;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * Password Based Key Derivation Function 2.
 *
 * @author Guillaume Wallet
 * @since 4.2.2
 * @see <a href="https://tools.ietf.org/html/rfc2898">Password-Based Cryptography Specification Version 2.0</a>
 */
public final class PBKDF2 {
	/**
	 * @see <a href="http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html#SecretKeyFactory">Java 6 runtime's SecretKeyFactory</a>
	 * @see <a href="http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#SecretKeyFactory">Java 7 runtime's SecretKeyFactory</a>
	 */
	public static final String WITH_HMAC_SHA1 = "PBKDF2WithHmacSHA1";
	/**
	 * @see <a href="http://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SecretKeyFactory">Java 8 runtime's SecretKeyFactory</a>
	 */
	public static final String WITH_HMAC_SHA256 = "PBKDF2WithHmacSHA256";
	/**
	 * @see <a href="http://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SecretKeyFactory">Java 8 runtime's SecretKeyFactory</a>
	 */
	public static final String WITH_HMAC_SHA512 = "PBKDF2WithHmacSHA512";

	private final SecretKeyFactory secretKeyFactory;

	/**
	 * Constructs a key derivation function with HMAC-SHA1 as the underlying pseudo-random function.
	 *
	 * @see #WITH_HMAC_SHA1
	 */
	public PBKDF2() {
		this(WITH_HMAC_SHA1);
	}

	/**
	 * Constructs a key derivation function with the given underlying pseudo-random function.
	 *
	 * @param algorithm the secret key factory algorithm, can be one of {@code "PBKDF2WithHmacSHA1"} (default),
	 * 			{@code "PBKDF2WithHmacSHA256"}, {@code "PBKDF2WithHmacSHA512"}, depending on the target runtime version.
	 *
	 * @see #WITH_HMAC_SHA1
	 * @see #WITH_HMAC_SHA256
	 * @see #WITH_HMAC_SHA512
	 * @see <a href="http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html#SecretKeyFactory">Java 6 runtime's SecretKeyFactory</a>
	 * @see <a href="http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#SecretKeyFactory">Java 7 runtime's SecretKeyFactory</a>
	 * @see <a href="http://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SecretKeyFactory">Java 8 runtime's SecretKeyFactory</a>
	 */
	public PBKDF2(String algorithm) {
		try {
			this.secretKeyFactory = SecretKeyFactory.getInstance(algorithm);
		} catch (NoSuchAlgorithmException cause) {
			throw new IllegalArgumentException("Could not create PBKDF2 instance " + algorithm, cause);
		}
	}

	public byte[] encode(String password, byte[] salt, int iterations, int hashLengthInByte) {
		PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, hashLengthInByte * 8);
		try {
			return secretKeyFactory.generateSecret(spec).getEncoded();
		} catch (InvalidKeySpecException cause) { throw new IllegalStateException("Can not create hash", cause); } // Should never happen
	}
}
