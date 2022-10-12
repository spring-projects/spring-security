/*
 * Copyright 2002-2022 the original author or authors.
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

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.util.EncodingUtils;

/**
 * A {@link PasswordEncoder} implementation that uses PBKDF2 with :
 * <ul>
 * <li>a configurable random salt value length (default is {@value #DEFAULT_SALT_LENGTH}
 * bytes)</li>
 * <li>a configurable number of iterations (default is {@value #DEFAULT_ITERATIONS})</li>
 * <li>a configurable key derivation function (see {@link SecretKeyFactoryAlgorithm})</li>
 * <li>a configurable secret appended to the random salt (default is empty)</li>
 * </ul>
 * The algorithm is invoked on the concatenated bytes of the salt, secret and password.
 *
 * @author Rob Worsnop
 * @author Rob Winch
 * @author Loïc Guibert
 * @since 4.1
 */
public class Pbkdf2PasswordEncoder implements PasswordEncoder {

	private static final int DEFAULT_SALT_LENGTH = 16;

	private static final SecretKeyFactoryAlgorithm DEFAULT_ALGORITHM = SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256;

	private static final int DEFAULT_HASH_WIDTH = 256; // SHA-256

	private static final int DEFAULT_ITERATIONS = 310000;

	private final BytesKeyGenerator saltGenerator;

	private final byte[] secret;

	private final int iterations;

	private String algorithm = DEFAULT_ALGORITHM.name();

	private int hashWidth = DEFAULT_HASH_WIDTH;

	// @formatter:off
	/*
	The length of the hash should be derived from the hashing algorithm.

	For example:
		SHA-1 - 160 bits (20 bytes)
		SHA-256 - 256 bits (32 bytes)
		SHA-512 - 512 bits (64 bytes)

	However, the original configuration for PBKDF2 was hashWidth=256 and algorithm=SHA-1, which is incorrect.
	The default configuration has been updated to hashWidth=256 and algorithm=SHA-256 (see gh-10506).
	In order to preserve backwards compatibility, the variable 'overrideHashWidth' has been introduced
	to indicate usage of the deprecated constructor that honors the hashWidth parameter.
	 */
	// @formatter:on
	private boolean overrideHashWidth = true;

	private boolean encodeHashAsBase64;

	/**
	 * Constructs a PBKDF2 password encoder with a secret value as well as salt length,
	 * iterations and hash width.
	 * @param secret the secret
	 * @param saltLength the salt length (in bytes)
	 * @param iterations the number of iterations. Users should aim for taking about .5
	 * seconds on their own system.
	 * @param hashWidth the size of the hash (in bits)
	 * @since 5.5
	 * @deprecated Use
	 * {@link #Pbkdf2PasswordEncoder(CharSequence, int, int, SecretKeyFactoryAlgorithm)}
	 * instead
	 */
	@Deprecated
	public Pbkdf2PasswordEncoder(CharSequence secret, int saltLength, int iterations, int hashWidth) {
		this.secret = Utf8.encode(secret);
		this.saltGenerator = KeyGenerators.secureRandom(saltLength);
		this.iterations = iterations;
		this.hashWidth = hashWidth;
		this.algorithm = SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA1.name();
		this.overrideHashWidth = false; // Honor 'hashWidth' to preserve backwards
										// compatibility
	}

	/**
	 * Constructs a PBKDF2 password encoder with a secret value as well as salt length,
	 * iterations and algorithm.
	 * @param secret the secret
	 * @param saltLength the salt length (in bytes)
	 * @param iterations the number of iterations. Users should aim for taking about .5
	 * seconds on their own system.
	 * @param secretKeyFactoryAlgorithm the algorithm to use
	 * @since 5.8
	 */
	public Pbkdf2PasswordEncoder(CharSequence secret, int saltLength, int iterations,
			SecretKeyFactoryAlgorithm secretKeyFactoryAlgorithm) {
		this.secret = Utf8.encode(secret);
		this.saltGenerator = KeyGenerators.secureRandom(saltLength);
		this.iterations = iterations;
		setAlgorithm(secretKeyFactoryAlgorithm);
	}

	/**
	 * Constructs a PBKDF2 password encoder with no additional secret value. There will be
	 * a salt length of 8 bytes, 185,000 iterations, SHA-1 algorithm and a hash length of
	 * 256 bits. The default is based upon aiming for .5 seconds to validate the password
	 * when this class was added. Users should tune password verification to their own
	 * systems.
	 * @return the {@link Pbkdf2PasswordEncoder}
	 * @since 5.8
	 * @deprecated Use {@link #defaultsForSpringSecurity_v5_8()} instead
	 */
	@Deprecated
	public static Pbkdf2PasswordEncoder defaultsForSpringSecurity_v5_5() {
		return new Pbkdf2PasswordEncoder("", 8, 185000, 256);
	}

	/**
	 * Constructs a PBKDF2 password encoder with no additional secret value. There will be
	 * a salt length of 16 bytes, 310,000 iterations, SHA-256 algorithm and a hash length
	 * of 256 bits. The default is based upon aiming for .5 seconds to validate the
	 * password when this class was added. Users should tune password verification to
	 * their own systems.
	 * @return the {@link Pbkdf2PasswordEncoder}
	 * @since 5.8
	 */
	public static Pbkdf2PasswordEncoder defaultsForSpringSecurity_v5_8() {
		return new Pbkdf2PasswordEncoder("", DEFAULT_SALT_LENGTH, DEFAULT_ITERATIONS, DEFAULT_ALGORITHM);
	}

	/**
	 * Sets the algorithm to use. See <a href=
	 * "https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SecretKeyFactory">SecretKeyFactory
	 * Algorithms</a>
	 * @param secretKeyFactoryAlgorithm the algorithm to use (i.e.
	 * {@code SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA1},
	 * {@code SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256},
	 * {@code SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA512})
	 * @since 5.0
	 */
	public void setAlgorithm(SecretKeyFactoryAlgorithm secretKeyFactoryAlgorithm) {
		if (secretKeyFactoryAlgorithm == null) {
			throw new IllegalArgumentException("secretKeyFactoryAlgorithm cannot be null");
		}
		String algorithmName = secretKeyFactoryAlgorithm.name();
		try {
			SecretKeyFactory.getInstance(algorithmName);
			this.algorithm = algorithmName;
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalArgumentException("Invalid algorithm '" + algorithmName + "'.", ex);
		}
		if (this.overrideHashWidth) {
			this.hashWidth = SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA1.equals(secretKeyFactoryAlgorithm) ? 160
					: SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256.equals(secretKeyFactoryAlgorithm) ? 256 : 512;
		}
	}

	/**
	 * Sets if the resulting hash should be encoded as Base64. The default is false which
	 * means it will be encoded in Hex.
	 * @param encodeHashAsBase64 true if encode as Base64, false if should use Hex
	 * (default)
	 */
	public void setEncodeHashAsBase64(boolean encodeHashAsBase64) {
		this.encodeHashAsBase64 = encodeHashAsBase64;
	}

	@Override
	public String encode(CharSequence rawPassword) {
		byte[] salt = this.saltGenerator.generateKey();
		byte[] encoded = encode(rawPassword, salt);
		return encode(encoded);
	}

	private String encode(byte[] bytes) {
		if (this.encodeHashAsBase64) {
			return Base64.getEncoder().encodeToString(bytes);
		}
		return String.valueOf(Hex.encode(bytes));
	}

	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		byte[] digested = decode(encodedPassword);
		byte[] salt = EncodingUtils.subArray(digested, 0, this.saltGenerator.getKeyLength());
		return MessageDigest.isEqual(digested, encode(rawPassword, salt));
	}

	private byte[] decode(String encodedBytes) {
		if (this.encodeHashAsBase64) {
			return Base64.getDecoder().decode(encodedBytes);
		}
		return Hex.decode(encodedBytes);
	}

	private byte[] encode(CharSequence rawPassword, byte[] salt) {
		try {
			PBEKeySpec spec = new PBEKeySpec(rawPassword.toString().toCharArray(),
					EncodingUtils.concatenate(salt, this.secret), this.iterations, this.hashWidth);
			SecretKeyFactory skf = SecretKeyFactory.getInstance(this.algorithm);
			return EncodingUtils.concatenate(salt, skf.generateSecret(spec).getEncoded());
		}
		catch (GeneralSecurityException ex) {
			throw new IllegalStateException("Could not create hash", ex);
		}
	}

	/**
	 * The Algorithm used for creating the {@link SecretKeyFactory}
	 *
	 * @since 5.0
	 */
	public enum SecretKeyFactoryAlgorithm {

		PBKDF2WithHmacSHA1, PBKDF2WithHmacSHA256, PBKDF2WithHmacSHA512

	}

}
