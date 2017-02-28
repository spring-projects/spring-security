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

import org.springframework.security.crypto.codec.Codec;
import org.springframework.security.crypto.codec.Codecs;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.springframework.security.crypto.pbkdf2.PBKDF2.WITH_HMAC_SHA1;
import static org.springframework.security.crypto.util.EncodingUtils.concatenate;
import static org.springframework.security.crypto.util.EncodingUtils.subArray;
import static org.springframework.security.crypto.util.EncodingUtils.timeConstantArrayEquals;

/**
 * A {@link PasswordEncoder} implementation that rely on {@link PBKDF2} and is fully customizable.
 * <p>
 * The hash length can be configured, default value is 32 bytes (256 bits) long.<br/>
 * The salt length can be configured, default value is 8 bytes (64 bits) long.<br/>
 * The iteration count can be configured, default value is 185,000.<br/>
 * The key derivation function used can be configured, default value is {@code HmacSHA1}.<br/>
 * The default hash's {@link String} representation is {@link Codecs#hexadecimal() hexadecimal}.
 * <p>
 *
 * @author Guillaume Wallet
 * @since 4.2.2
 * @see <a href="https://tools.ietf.org/html/rfc2898">Password-Based Cryptography Specification Version 2.0</a>
 * @see PBKDF2
 * @see Codec
 */
public class PBKDF2PasswordEncoder implements PasswordEncoder {
	/** The default hash length is 32 bytes (256 bits) long. */
	public static final int DEFAULT_HASH_LENGTH = 32;
	/** The default salt length is 8 bytes (64 bits) long. */
	public static final int DEFAULT_SALT_LENGTH = 8;
	/** The default iterations count is 185,000. */
	public static final int DEFAULT_ITERATION_COUNT = 185000;
	private BytesKeyGenerator saltGenerator;
	private int hashLength;
	private int iterations;
	private PBKDF2 keyDerivationFunction;
	private Codec codec;

	/**
	 * Constructs a password encoder with defined settings and produces hexadecimal footprint
	 * using HMAC-SHA1 as key derivation function.
	 * The salt will be 8 bytes long (64 bits), the hash will be 32 bytes long (256 bits) produced
	 * by iterating 185 000 times.
	 */
	public PBKDF2PasswordEncoder() {
		this(DEFAULT_SALT_LENGTH, DEFAULT_HASH_LENGTH, DEFAULT_ITERATION_COUNT);
	}

	/**
	 * Constructs a password encoder with defined settings and produces hexadecimal footprint
	 * using HmacSHA1 as key derivation function.
	 *
	 * @param saltLength Length in bytes of the generated salt.
	 * @param hashLength Length in bytes of the produced hash.
	 * @param iterations Number of iterations to produce the hash.
	 */
	public PBKDF2PasswordEncoder(int saltLength, int hashLength, int iterations) {
		this(saltLength, hashLength, iterations, new PBKDF2(WITH_HMAC_SHA1));
	}

	/**
	 * Constructs a password encoder with defined settings and produces hexadecimal footprint.
	 *
	 * @param saltLength Length in bytes of the generated salt.
	 * @param hashLength Length in bytes of the produced hash.
	 * @param iterations Number of iterations to produce the hash.
	 * @param keyDerivationFunction The key derivation function to use.
	 */
	public PBKDF2PasswordEncoder(int saltLength, int hashLength, int iterations, PBKDF2 keyDerivationFunction) {
		this(saltLength, hashLength, iterations, keyDerivationFunction, Codecs.hexadecimal());
	}

	/**
	 * Constructs a password encoder with defined settings.
	 *
	 * @param saltLength Length in bytes of the generated salt.
	 * @param hashLength Length in bytes of the produced hash.
	 * @param iterations Number of iterations to produce the hash.
	 * @param keyDerivationFunction The key derivation function to use.
	 * @param codec The codec to use when encoding into {@code java.lang.String}.
	 */
	public PBKDF2PasswordEncoder(int saltLength, int hashLength, int iterations, PBKDF2 keyDerivationFunction, Codec codec) {
		this.iterations = iterations;
		this.hashLength = hashLength;
		this.saltGenerator = KeyGenerators.secureRandom(saltLength);
		this.keyDerivationFunction = keyDerivationFunction;
		this.codec = codec;
	}

	@Override
	public String encode(CharSequence rawPassword) {
		byte[] salt = saltGenerator.generateKey();
		byte[] encoded = doEncode(rawPassword, salt);
		return codec.encode(concatenate(salt, encoded));
	}

	/*
	 * Execute the same algorithm for #encode(CharSequence) and #matches(CharSequence, String)
	 */
	protected byte[] doEncode(CharSequence rawPassword, byte[] salt) {
		return keyDerivationFunction.encode(rawPassword.toString(), salt, iterations, hashLength);
	}

	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		byte[] footprint = codec.decode(encodedPassword);
		byte[] salt = subArray(footprint, 0, saltGenerator.getKeyLength());
		byte[] encoded = subArray(footprint, salt.length, footprint.length);
		return timeConstantArrayEquals(encoded, doEncode(rawPassword, salt));
	}
}
