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
import com.password4j.Argon2Function;

/**
 * Implementation of {@link org.springframework.security.crypto.password.PasswordEncoder}
 * that uses the Password4j library with Argon2 hashing algorithm.
 *
 * <p>
 * Argon2 is the winner of the Password Hashing Competition (2015) and is recommended for
 * new applications. It provides excellent resistance against GPU-based attacks and
 * includes built-in salt generation. This implementation leverages Password4j's Argon2
 * support which properly includes the salt in the output hash.
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
 * // Using default Argon2 settings (recommended)
 * PasswordEncoder encoder = new Argon2Password4jPasswordEncoder();
 *
 * // Using custom Argon2 configuration
 * PasswordEncoder customEncoder = new Argon2Password4jPasswordEncoder(
 *     Argon2Function.getInstance(65536, 3, 4, 32, Argon2.ID));
 * }</pre>
 *
 * @author Mehrdad Bozorgmehr
 * @since 7.0
 * @see Argon2Function
 * @see AlgorithmFinder#getArgon2Instance()
 */
public class Argon2Password4jPasswordEncoder extends Password4jPasswordEncoder {

	/**
	 * Constructs an Argon2 password encoder using the default Argon2 configuration from
	 * Password4j's AlgorithmFinder.
	 */
	public Argon2Password4jPasswordEncoder() {
		super(AlgorithmFinder.getArgon2Instance());
	}

	/**
	 * Constructs an Argon2 password encoder with a custom Argon2 function.
	 * @param argon2Function the Argon2 function to use for encoding passwords, must not
	 * be null
	 * @throws IllegalArgumentException if argon2Function is null
	 */
	public Argon2Password4jPasswordEncoder(Argon2Function argon2Function) {
		super(argon2Function);
	}

}
