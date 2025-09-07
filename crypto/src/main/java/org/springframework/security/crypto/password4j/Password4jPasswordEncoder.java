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

import com.password4j.AlgorithmFinder;
import com.password4j.Hash;
import com.password4j.HashingFunction;
import com.password4j.Password;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.crypto.password.AbstractValidatingPasswordEncoder;
import org.springframework.util.Assert;

/**
 * Implementation of {@link org.springframework.security.crypto.password.PasswordEncoder}
 * that uses the Password4j library. This encoder supports multiple password hashing
 * algorithms including BCrypt, SCrypt, Argon2, and PBKDF2.
 *
 * <p>
 * The encoder uses the provided {@link HashingFunction} for both encoding and
 * verification. Password4j can automatically detect the algorithm used in existing hashes
 * during verification.
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
 * // Using default algorithms from AlgorithmFinder (recommended approach)
 * PasswordEncoder bcryptEncoder = new Password4jPasswordEncoder(AlgorithmFinder.getBcryptInstance());
 * PasswordEncoder argon2Encoder = new Password4jPasswordEncoder(AlgorithmFinder.getArgon2Instance());
 * PasswordEncoder scryptEncoder = new Password4jPasswordEncoder(AlgorithmFinder.getScryptInstance());
 * PasswordEncoder pbkdf2Encoder = new Password4jPasswordEncoder(AlgorithmFinder.getPBKDF2Instance());
 *
 * // Using customized algorithm parameters
 * PasswordEncoder customBcrypt = new Password4jPasswordEncoder(BcryptFunction.getInstance(12));
 * PasswordEncoder customArgon2 = new Password4jPasswordEncoder(
 *     Argon2Function.getInstance(65536, 3, 4, 32, Argon2.ID));
 * PasswordEncoder customScrypt = new Password4jPasswordEncoder(
 *     ScryptFunction.getInstance(32768, 8, 1, 32));
 * PasswordEncoder customPbkdf2 = new Password4jPasswordEncoder(
 *     CompressedPBKDF2Function.getInstance("SHA256", 310000, 32));
 * }</pre>
 *
 * @author Mehrdad Bozorgmehr
 * @since 7.0
 * @see AlgorithmFinder
 */
public class Password4jPasswordEncoder extends AbstractValidatingPasswordEncoder {

	private final Log logger = LogFactory.getLog(getClass());

	private final HashingFunction hashingFunction;

	/**
	 * Constructs a Password4j password encoder with the specified hashing function.
	 *
	 * <p>
	 * It is recommended to use password4j's {@link AlgorithmFinder} to obtain default
	 * instances with secure configurations:
	 * </p>
	 * <ul>
	 * <li>{@code AlgorithmFinder.getBcryptInstance()} - BCrypt with default settings</li>
	 * <li>{@code AlgorithmFinder.getArgon2Instance()} - Argon2 with default settings</li>
	 * <li>{@code AlgorithmFinder.getScryptInstance()} - SCrypt with default settings</li>
	 * <li>{@code AlgorithmFinder.getPBKDF2Instance()} - PBKDF2 with default settings</li>
	 * </ul>
	 *
	 * <p>
	 * For custom configurations, you can create specific function instances:
	 * </p>
	 * <ul>
	 * <li>{@code BcryptFunction.getInstance(12)} - BCrypt with 12 rounds</li>
	 * <li>{@code Argon2Function.getInstance(65536, 3, 4, 32, Argon2.ID)} - Custom
	 * Argon2</li>
	 * <li>{@code ScryptFunction.getInstance(16384, 8, 1, 32)} - Custom SCrypt</li>
	 * <li>{@code CompressedPBKDF2Function.getInstance("SHA256", 310000, 32)} - Custom
	 * PBKDF2</li>
	 * </ul>
	 * @param hashingFunction the hashing function to use for encoding passwords, must not
	 * be null
	 * @throws IllegalArgumentException if hashingFunction is null
	 */
	public Password4jPasswordEncoder(HashingFunction hashingFunction) {
		Assert.notNull(hashingFunction, "hashingFunction cannot be null");
		this.hashingFunction = hashingFunction;
	}

	@Override
	protected String encodeNonNullPassword(String rawPassword) {
		try {
			Hash hash = Password.hash(rawPassword).with(this.hashingFunction);
			return hash.getResult();
		}
		catch (Exception ex) {
			throw new IllegalStateException("Failed to encode password using Password4j", ex);
		}
	}

	@Override
	protected boolean matchesNonNull(String rawPassword, String encodedPassword) {
		try {
			// Use the specific hashing function for verification
			return Password.check(rawPassword, encodedPassword).with(this.hashingFunction);
		}
		catch (Exception ex) {
			this.logger.warn("Password verification failed for encoded password: " + encodedPassword, ex);
			return false;
		}
	}

	@Override
	protected boolean upgradeEncodingNonNull(String encodedPassword) {
		// Password4j handles upgrade detection internally for most algorithms
		// For now, we'll return false to maintain existing behavior
		return false;
	}

}
