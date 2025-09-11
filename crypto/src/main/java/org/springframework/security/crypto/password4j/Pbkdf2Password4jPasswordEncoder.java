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

import java.security.SecureRandom;
import java.util.Base64;

import com.password4j.AlgorithmFinder;
import com.password4j.Hash;
import com.password4j.PBKDF2Function;
import com.password4j.Password;

import org.springframework.security.crypto.password.AbstractValidatingPasswordEncoder;
import org.springframework.util.Assert;

/**
 * Implementation of {@link org.springframework.security.crypto.password.PasswordEncoder}
 * that uses the Password4j library with PBKDF2 hashing algorithm.
 *
 * <p>
 * PBKDF2 is a key derivation function designed to be computationally expensive to thwart
 * dictionary and brute force attacks. This implementation handles the salt management
 * explicitly since Password4j's PBKDF2 implementation does not include the salt in the
 * output hash.
 * </p>
 *
 * <p>
 * The encoded password format is: {salt}:{hash} where both salt and hash are Base64
 * encoded.
 * </p>
 *
 * <p>
 * This implementation is thread-safe and can be shared across multiple threads.
 * </p>
 *
 * <p>
 * <strong>Usage Examples:</strong>
 * </p>
 * <pre>{@code
 * // Using default PBKDF2 settings (recommended)
 * PasswordEncoder encoder = new Pbkdf2Password4jPasswordEncoder();
 *
 * // Using custom PBKDF2 function
 * PasswordEncoder customEncoder = new Pbkdf2Password4jPasswordEncoder(
 *     PBKDF2Function.getInstance(Algorithm.HMAC_SHA256, 100000, 256));
 * }</pre>
 *
 * @author Mehrdad Bozorgmehr
 * @since 7.0
 * @see PBKDF2Function
 * @see AlgorithmFinder#getPBKDF2Instance()
 */
public class Pbkdf2Password4jPasswordEncoder extends AbstractValidatingPasswordEncoder {

	private static final String DELIMITER = ":";

	private static final int DEFAULT_SALT_LENGTH = 32;

	private final PBKDF2Function pbkdf2Function;

	private final SecureRandom secureRandom;

	private final int saltLength;

	/**
	 * Constructs a PBKDF2 password encoder using the default PBKDF2 configuration from
	 * Password4j's AlgorithmFinder.
	 */
	public Pbkdf2Password4jPasswordEncoder() {
		this(AlgorithmFinder.getPBKDF2Instance());
	}

	/**
	 * Constructs a PBKDF2 password encoder with a custom PBKDF2 function.
	 * @param pbkdf2Function the PBKDF2 function to use for encoding passwords, must not
	 * be null
	 * @throws IllegalArgumentException if pbkdf2Function is null
	 */
	public Pbkdf2Password4jPasswordEncoder(PBKDF2Function pbkdf2Function) {
		this(pbkdf2Function, DEFAULT_SALT_LENGTH);
	}

	/**
	 * Constructs a PBKDF2 password encoder with a custom PBKDF2 function and salt length.
	 * @param pbkdf2Function the PBKDF2 function to use for encoding passwords, must not
	 * be null
	 * @param saltLength the length of the salt in bytes, must be positive
	 * @throws IllegalArgumentException if pbkdf2Function is null or saltLength is not
	 * positive
	 */
	public Pbkdf2Password4jPasswordEncoder(PBKDF2Function pbkdf2Function, int saltLength) {
		Assert.notNull(pbkdf2Function, "pbkdf2Function cannot be null");
		Assert.isTrue(saltLength > 0, "saltLength must be positive");
		this.pbkdf2Function = pbkdf2Function;
		this.saltLength = saltLength;
		this.secureRandom = new SecureRandom();
	}

	@Override
	protected String encodeNonNullPassword(String rawPassword) {
		byte[] salt = new byte[this.saltLength];
		this.secureRandom.nextBytes(salt);

		Hash hash = Password.hash(rawPassword).addSalt(salt).with(this.pbkdf2Function);
		String encodedSalt = Base64.getEncoder().encodeToString(salt);
		String encodedHash = hash.getResult();

		return encodedSalt + DELIMITER + encodedHash;
	}

	@Override
	protected boolean matchesNonNull(String rawPassword, String encodedPassword) {
		if (!encodedPassword.contains(DELIMITER)) {
			return false;
		}

		String[] parts = encodedPassword.split(DELIMITER, 2);
		if (parts.length != 2) {
			return false;
		}

		try {
			byte[] salt = Base64.getDecoder().decode(parts[0]);
			String expectedHash = parts[1];

			Hash hash = Password.hash(rawPassword).addSalt(salt).with(this.pbkdf2Function);
			return expectedHash.equals(hash.getResult());
		}
		catch (IllegalArgumentException ex) {
			// Invalid Base64 encoding
			return false;
		}
	}

	@Override
	protected boolean upgradeEncodingNonNull(String encodedPassword) {
		// For now, we'll return false to maintain existing behavior
		// This could be enhanced in the future to check if the encoding parameters
		// match the current configuration
		return false;
	}

}
