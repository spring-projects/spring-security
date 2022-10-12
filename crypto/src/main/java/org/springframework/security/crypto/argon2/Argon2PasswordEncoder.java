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

package org.springframework.security.crypto.argon2;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * <p>
 * Implementation of PasswordEncoder that uses the Argon2 hashing function. Clients can
 * optionally supply the length of the salt to use, the length of the generated hash, a
 * cpu cost parameter, a memory cost parameter and a parallelization parameter.
 * </p>
 *
 * <p>
 * Note:
 * </p>
 * <p>
 * The currently implementation uses Bouncy castle which does not exploit
 * parallelism/optimizations that password crackers will, so there is an unnecessary
 * asymmetry between attacker and defender.
 * </p>
 *
 * @author Simeon Macke
 * @since 5.3
 */
public class Argon2PasswordEncoder implements PasswordEncoder {

	private static final int DEFAULT_SALT_LENGTH = 16;

	private static final int DEFAULT_HASH_LENGTH = 32;

	private static final int DEFAULT_PARALLELISM = 1;

	private static final int DEFAULT_MEMORY = 1 << 14;

	private static final int DEFAULT_ITERATIONS = 2;

	private final Log logger = LogFactory.getLog(getClass());

	private final int hashLength;

	private final int parallelism;

	private final int memory;

	private final int iterations;

	private final BytesKeyGenerator saltGenerator;

	/**
	 * Constructs an Argon2 password encoder with the provided parameters.
	 * @param saltLength the salt length (in bytes)
	 * @param hashLength the hash length (in bytes)
	 * @param parallelism the parallelism
	 * @param memory the memory cost
	 * @param iterations the number of iterations
	 */
	public Argon2PasswordEncoder(int saltLength, int hashLength, int parallelism, int memory, int iterations) {
		this.hashLength = hashLength;
		this.parallelism = parallelism;
		this.memory = memory;
		this.iterations = iterations;
		this.saltGenerator = KeyGenerators.secureRandom(saltLength);
	}

	/**
	 * Constructs an Argon2 password encoder with a salt length of 16 bytes, a hash length
	 * of 32 bytes, parallelism of 1, memory cost of 1 << 12 and 3 iterations.
	 * @return the {@link Argon2PasswordEncoder}
	 * @since 5.8
	 * @deprecated Use {@link #defaultsForSpringSecurity_v5_8()} instead
	 */
	@Deprecated
	public static Argon2PasswordEncoder defaultsForSpringSecurity_v5_2() {
		return new Argon2PasswordEncoder(16, 32, 1, 1 << 12, 3);
	}

	/**
	 * Constructs an Argon2 password encoder with a salt length of 16 bytes, a hash length
	 * of 32 bytes, parallelism of 1, memory cost of 1 << 14 and 2 iterations.
	 * @return the {@link Argon2PasswordEncoder}
	 * @since 5.8
	 */
	public static Argon2PasswordEncoder defaultsForSpringSecurity_v5_8() {
		return new Argon2PasswordEncoder(DEFAULT_SALT_LENGTH, DEFAULT_HASH_LENGTH, DEFAULT_PARALLELISM, DEFAULT_MEMORY,
				DEFAULT_ITERATIONS);
	}

	@Override
	public String encode(CharSequence rawPassword) {
		byte[] salt = this.saltGenerator.generateKey();
		byte[] hash = new byte[this.hashLength];
		// @formatter:off
		Argon2Parameters params = new Argon2Parameters
				.Builder(Argon2Parameters.ARGON2_id)
				.withSalt(salt)
				.withParallelism(this.parallelism)
				.withMemoryAsKB(this.memory)
				.withIterations(this.iterations)
				.build();
		// @formatter:on
		Argon2BytesGenerator generator = new Argon2BytesGenerator();
		generator.init(params);
		generator.generateBytes(rawPassword.toString().toCharArray(), hash);
		return Argon2EncodingUtils.encode(hash, params);
	}

	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		if (encodedPassword == null) {
			this.logger.warn("password hash is null");
			return false;
		}
		Argon2EncodingUtils.Argon2Hash decoded;
		try {
			decoded = Argon2EncodingUtils.decode(encodedPassword);
		}
		catch (IllegalArgumentException ex) {
			this.logger.warn("Malformed password hash", ex);
			return false;
		}
		byte[] hashBytes = new byte[decoded.getHash().length];
		Argon2BytesGenerator generator = new Argon2BytesGenerator();
		generator.init(decoded.getParameters());
		generator.generateBytes(rawPassword.toString().toCharArray(), hashBytes);
		return constantTimeArrayEquals(decoded.getHash(), hashBytes);
	}

	@Override
	public boolean upgradeEncoding(String encodedPassword) {
		if (encodedPassword == null || encodedPassword.length() == 0) {
			this.logger.warn("password hash is null");
			return false;
		}
		Argon2Parameters parameters = Argon2EncodingUtils.decode(encodedPassword).getParameters();
		return parameters.getMemory() < this.memory || parameters.getIterations() < this.iterations;
	}

	private static boolean constantTimeArrayEquals(byte[] expected, byte[] actual) {
		if (expected.length != actual.length) {
			return false;
		}
		int result = 0;
		for (int i = 0; i < expected.length; i++) {
			result |= expected[i] ^ actual[i];
		}
		return result == 0;
	}

}
