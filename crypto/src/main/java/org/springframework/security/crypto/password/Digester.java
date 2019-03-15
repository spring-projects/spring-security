/*
 * Copyright 2011-2018 the original author or authors.
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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Helper for working with the MessageDigest API.
 *
 * Performs the configured number of iterations of the hashing algorithm per digest to aid
 * in protecting against brute force attacks.
 *
 * @author Keith Donald
 * @author Luke Taylor
 */
final class Digester {

	private final String algorithm;

	private int iterations;

	/**
	 * Create a new Digester.
	 * @param algorithm the digest algorithm; for example, "SHA-1" or "SHA-256".
	 * @param iterations the number of times to apply the digest algorithm to the input
	 */
	public Digester(String algorithm, int iterations) {
		// eagerly validate the algorithm
		createDigest(algorithm);
		this.algorithm = algorithm;
		setIterations(iterations);
	}

	public byte[] digest(byte[] value) {
		MessageDigest messageDigest = createDigest(algorithm);
		for (int i = 0; i < iterations; i++) {
			value = messageDigest.digest(value);
		}
		return value;
	}

	final void setIterations(int iterations) {
		if (iterations <= 0) {
			throw new IllegalArgumentException("Iterations value must be greater than zero");
		}
		this.iterations = iterations;
	}

	private static MessageDigest createDigest(String algorithm) {
		try {
			return MessageDigest.getInstance(algorithm);
		}
		catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("No such hashing algorithm", e);
		}
	}
}
