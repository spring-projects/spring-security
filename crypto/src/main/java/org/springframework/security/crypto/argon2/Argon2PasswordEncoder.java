/*
 * Copyright 2002-2019 the original author or authors.
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

	private static final int DEFAULT_MEMORY = 1 << 12;

	private static final int DEFAULT_ITERATIONS = 3;

	private final Log logger = LogFactory.getLog(getClass());

	private final int hashLength;

	private final int parallelism;

	private final int memory;

	private final int iterations;

	private final BytesKeyGenerator saltGenerator;

	public Argon2PasswordEncoder(int saltLength, int hashLength, int parallelism, int memory, int iterations) {
		this.hashLength = hashLength;
		this.parallelism = parallelism;
		this.memory = memory;
		this.iterations = iterations;

		this.saltGenerator = KeyGenerators.secureRandom(saltLength);
	}

	public Argon2PasswordEncoder() {
		this(DEFAULT_SALT_LENGTH, DEFAULT_HASH_LENGTH, DEFAULT_PARALLELISM, DEFAULT_MEMORY, DEFAULT_ITERATIONS);
	}

	@Override
	public String encode(CharSequence rawPassword) {
		byte[] salt = saltGenerator.generateKey();
		byte[] hash = new byte[hashLength];

		Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id).withSalt(salt)
				.withParallelism(parallelism).withMemoryAsKB(memory).withIterations(iterations).build();
		Argon2BytesGenerator generator = new Argon2BytesGenerator();
		generator.init(params);
		generator.generateBytes(rawPassword.toString().toCharArray(), hash);

		return Argon2EncodingUtils.encode(hash, params);
	}

	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		if (encodedPassword == null) {
			logger.warn("password hash is null");
			return false;
		}

		Argon2EncodingUtils.Argon2Hash decoded;

		try {
			decoded = Argon2EncodingUtils.decode(encodedPassword);
		}
		catch (IllegalArgumentException e) {
			logger.warn("Malformed password hash", e);
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
			logger.warn("password hash is null");
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
