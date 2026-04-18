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
import com.password4j.BalloonHashingFunction;
import com.password4j.HashBuilder;
import com.password4j.Password;
import org.jspecify.annotations.Nullable;

import org.springframework.security.crypto.password.AbstractValidatingPasswordEncoder;
import org.springframework.util.Assert;

/**
 * Implementation of {@link org.springframework.security.crypto.password.PasswordEncoder}
 * that uses the Password4j library with Balloon hashing algorithm.
 *
 * <p>
 * Balloon hashing is a memory-hard password hashing algorithm designed to be resistant to
 * both time-memory trade-off attacks and side-channel attacks. This implementation
 * handles the salt management explicitly since Password4j's Balloon hashing
 * implementation does not include the salt in the output hash.
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
 * // Using default Balloon hashing settings (recommended)
 * PasswordEncoder encoder = new BalloonHashingPassword4jPasswordEncoder();
 *
 * // Using custom Balloon hashing function
 * PasswordEncoder customEncoder = new BalloonHashingPassword4jPasswordEncoder(
 *     BalloonHashingFunction.getInstance(1024, 3, 4, "SHA-256"));
 * }</pre>
 *
 * @author Mehrdad Bozorgmehr
 * @author Andrey Litvitski
 * @since 7.0
 * @see BalloonHashingFunction
 * @see AlgorithmFinder#getBalloonHashingInstance()
 */
public class BalloonHashingPassword4jPasswordEncoder extends AbstractValidatingPasswordEncoder {

	private static final String DELIMITER = ":";

	private static final int DEFAULT_SALT_LENGTH = 32;

	private final BalloonHashingFunction balloonHashingFunction;

	private final SecureRandom secureRandom;

	private final int saltLength;

	@Nullable private final String pepper;

	/**
	 * Constructs a Balloon hashing password encoder using the default Balloon hashing
	 * configuration from Password4j's AlgorithmFinder.
	 */
	public BalloonHashingPassword4jPasswordEncoder() {
		this(AlgorithmFinder.getBalloonHashingInstance());
	}

	/**
	 * Constructs a Balloon hashing password encoder with a custom Balloon hashing
	 * function.
	 * @param balloonHashingFunction the Balloon hashing function to use for encoding
	 * passwords, must not be null
	 * @throws IllegalArgumentException if balloonHashingFunction is null
	 */
	public BalloonHashingPassword4jPasswordEncoder(BalloonHashingFunction balloonHashingFunction) {
		this(balloonHashingFunction, DEFAULT_SALT_LENGTH);
	}

	/**
	 * Constructs a Balloon hashing password encoder with a custom Balloon hashing
	 * function and salt length.
	 * @param balloonHashingFunction the Balloon hashing function to use for encoding
	 * passwords, must not be null
	 * @param saltLength the length of the salt in bytes, must be positive
	 * @throws IllegalArgumentException if balloonHashingFunction is null or saltLength is
	 * not positive
	 */
	public BalloonHashingPassword4jPasswordEncoder(BalloonHashingFunction balloonHashingFunction, int saltLength) {
		this(balloonHashingFunction, saltLength, null);
	}

	/**
	 * Constructs a Balloon hashing password encoder with a custom Balloon hashing
	 * function, salt length, and a pepper.
	 * @param balloonHashingFunction the Balloon hashing function to use for encoding
	 * passwords, must not be null
	 * @param saltLength the length of the salt in bytes, must be positive
	 * @param pepper the pepper to be used in the hashing process. If null, no pepper will
	 * be applied.
	 * @throws IllegalArgumentException if balloonHashingFunction is null or saltLength is
	 * not positive
	 * @since 7.0
	 */
	public BalloonHashingPassword4jPasswordEncoder(BalloonHashingFunction balloonHashingFunction, int saltLength,
			@Nullable String pepper) {
		Assert.notNull(balloonHashingFunction, "balloonHashingFunction cannot be null");
		Assert.isTrue(saltLength > 0, "saltLength must be positive");
		this.balloonHashingFunction = balloonHashingFunction;
		this.saltLength = saltLength;
		this.secureRandom = new SecureRandom();
		this.pepper = pepper;
	}

	@Override
	protected String encodeNonNullPassword(String rawPassword) {
		byte[] salt = new byte[this.saltLength];
		this.secureRandom.nextBytes(salt);

		HashBuilder hashBuilder = Password.hash(rawPassword).addSalt(salt);
		if (this.pepper != null) {
			hashBuilder.addPepper(this.pepper);
		}
		String encodedSalt = Base64.getEncoder().encodeToString(salt);
		String encodedHash = hashBuilder.with(this.balloonHashingFunction).getResult();

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

			HashBuilder hashBuilder = Password.hash(rawPassword).addSalt(salt);
			if (this.pepper != null) {
				hashBuilder.addPepper(this.pepper);
			}
			return expectedHash.equals(hashBuilder.with(this.balloonHashingFunction).getResult());
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
