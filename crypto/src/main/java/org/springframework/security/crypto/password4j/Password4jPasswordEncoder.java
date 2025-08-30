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

import com.password4j.*;
import com.password4j.types.Argon2;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.crypto.password.AbstractValidatingPasswordEncoder;
import org.springframework.util.Assert;

/**
 * Implementation of {@link org.springframework.security.crypto.password.PasswordEncoder} that uses the Password4j library.
 * This encoder supports multiple password hashing algorithms including BCrypt, SCrypt, Argon2, and PBKDF2.
 *
 * <p>The encoder determines the algorithm used based on the algorithm type specified during construction.
 * For verification, it can automatically detect the algorithm used in existing hashes.</p>
 *
 * <p>This implementation is thread-safe and can be shared across multiple threads.</p>
 *
 * @author Mehrdad Bozorgmehr
 * @since 6.5
 */
public class Password4jPasswordEncoder extends AbstractValidatingPasswordEncoder {

	private final Log logger = LogFactory.getLog(getClass());

	private final HashingFunction hashingFunction;

	private final Password4jAlgorithm algorithm;


	/**
	 * Enumeration of supported Password4j algorithms.
	 */
	public enum Password4jAlgorithm {
		/**
		 * BCrypt algorithm.
		 */
		BCRYPT,
		/**
		 * SCrypt algorithm.
		 */
		SCRYPT,
		/**
		 * Argon2 algorithm.
		 */
		ARGON2,
		/**
		 * PBKDF2 algorithm.
		 */
		PBKDF2,
		/**
		 * Compressed PBKDF2 algorithm.
		 */
		COMPRESSED_PBKDF2
	}

	/**
	 * Constructs a Password4j password encoder with the default BCrypt algorithm.
	 */
	public Password4jPasswordEncoder() {
		this(Password4jAlgorithm.BCRYPT);
	}

	/**
	 * Constructs a Password4j password encoder with the specified algorithm using default parameters.
	 *
	 * @param algorithm the password hashing algorithm to use
	 */
	public Password4jPasswordEncoder(Password4jAlgorithm algorithm) {
		Assert.notNull(algorithm, "algorithm cannot be null");
		this.algorithm = algorithm;
		this.hashingFunction = createDefaultHashingFunction(algorithm);
	}

	/**
	 * Constructs a Password4j password encoder with a custom hashing function.
	 *
	 * @param hashingFunction the custom hashing function to use
	 * @param algorithm       the password hashing algorithm type
	 */
	public Password4jPasswordEncoder(HashingFunction hashingFunction, Password4jAlgorithm algorithm) {
		Assert.notNull(hashingFunction, "hashingFunction cannot be null");
		Assert.notNull(algorithm, "algorithm cannot be null");
		this.hashingFunction = hashingFunction;
		this.algorithm = algorithm;
	}

	/**
	 * Creates a Password4j password encoder with BCrypt algorithm and specified rounds.
	 *
	 * @param rounds the number of rounds (cost factor) for BCrypt
	 * @return a new Password4j password encoder
	 */
	public static Password4jPasswordEncoder bcrypt(int rounds) {
		return new Password4jPasswordEncoder(BcryptFunction.getInstance(rounds), Password4jAlgorithm.BCRYPT);
	}

	/**
	 * Creates a Password4j password encoder with SCrypt algorithm and specified parameters.
	 *
	 * @param workFactor       the work factor (N parameter)
	 * @param resources        the resources (r parameter)
	 * @param parallelization  the parallelization (p parameter)
	 * @param derivedKeyLength the derived key length
	 * @return a new Password4j password encoder
	 */
	public static Password4jPasswordEncoder scrypt(int workFactor, int resources, int parallelization, int derivedKeyLength) {
		return new Password4jPasswordEncoder(
				ScryptFunction.getInstance(workFactor, resources, parallelization, derivedKeyLength),
				Password4jAlgorithm.SCRYPT
		);
	}

	/**
	 * Creates a Password4j password encoder with Argon2 algorithm and specified parameters.
	 *
	 * @param memory       the memory cost
	 * @param iterations   the number of iterations
	 * @param parallelism  the parallelism
	 * @param outputLength the output length
	 * @param type         the Argon2 type
	 * @return a new Password4j password encoder
	 */
	public static Password4jPasswordEncoder argon2(int memory, int iterations, int parallelism, int outputLength, Argon2 type) {
		return new Password4jPasswordEncoder(
				Argon2Function.getInstance(memory, iterations, parallelism, outputLength, type),
				Password4jAlgorithm.ARGON2
		);
	}

	/**
	 * Creates a Password4j password encoder with PBKDF2 algorithm and specified parameters.
	 *
	 * @param iterations       the number of iterations
	 * @param derivedKeyLength the derived key length
	 * @return a new Password4j password encoder
	 */
	public static Password4jPasswordEncoder pbkdf2(int iterations, int derivedKeyLength) {
		return new Password4jPasswordEncoder(
				CompressedPBKDF2Function.getInstance("SHA256", iterations, derivedKeyLength),
				Password4jAlgorithm.PBKDF2
		);
	}

	/**
	 * Creates a Password4j password encoder with compressed PBKDF2 algorithm.
	 *
	 * @param iterations       the number of iterations
	 * @param derivedKeyLength the derived key length
	 * @return a new Password4j password encoder
	 */
	public static Password4jPasswordEncoder compressedPbkdf2(int iterations, int derivedKeyLength) {
		return new Password4jPasswordEncoder(
				CompressedPBKDF2Function.getInstance("SHA256", iterations, derivedKeyLength),
				Password4jAlgorithm.COMPRESSED_PBKDF2
		);
	}

	/**
	 * Creates a Password4j password encoder with default settings for Spring Security v5.8+.
	 * This uses BCrypt with 10 rounds.
	 *
	 * @return a new Password4j password encoder with recommended defaults
	 * @since 6.5
	 */
	public static Password4jPasswordEncoder defaultsForSpringSecurity() {
		return bcrypt(10);
	}

	@Override
	protected String encodeNonNullPassword(String rawPassword) {
		try {
			Hash hash = Password.hash(rawPassword).with(this.hashingFunction);
			return hash.getResult();
		} catch (Exception ex) {
			throw new IllegalStateException("Failed to encode password using Password4j", ex);
		}
	}

	@Override
	protected boolean matchesNonNull(String rawPassword, String encodedPassword) {
		try {
			// Use the specific hashing function for verification
			return Password.check(rawPassword, encodedPassword).with(this.hashingFunction);
		} catch (Exception ex) {
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

	/**
	 * Creates a default hashing function for the specified algorithm.
	 *
	 * @param algorithm the password hashing algorithm
	 * @return the default hashing function
	 */
	private static HashingFunction createDefaultHashingFunction(Password4jAlgorithm algorithm) {
        return switch (algorithm) {
            case BCRYPT -> BcryptFunction.getInstance(10); // Default 10 rounds
            case SCRYPT -> ScryptFunction.getInstance(16384, 8, 1, 32); // Default parameters
            case ARGON2 -> Argon2Function.getInstance(65536, 3, 4, 32, Argon2.ID); // Default parameters
            case PBKDF2 ->
                    CompressedPBKDF2Function.getInstance("SHA256", 310000, 32); // Use compressed format for self-contained encoding
            case COMPRESSED_PBKDF2 -> CompressedPBKDF2Function.getInstance("SHA256", 310000, 32);
        };
	}

	/**
	 * Gets the algorithm used by this encoder.
	 *
	 * @return the password hashing algorithm
	 */
	public Password4jAlgorithm getAlgorithm() {
		return this.algorithm;
	}

	/**
	 * Gets the hashing function used by this encoder.
	 *
	 * @return the hashing function
	 */
	public HashingFunction getHashingFunction() {
		return this.hashingFunction;
	}

}
