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
import com.password4j.ScryptFunction;

/**
 * Implementation of {@link org.springframework.security.crypto.password.PasswordEncoder}
 * that uses the Password4j library with SCrypt hashing algorithm.
 *
 * <p>
 * SCrypt is a memory-hard password hashing algorithm designed to be resistant to hardware
 * brute-force attacks. It includes built-in salt generation and is particularly effective
 * against ASIC and GPU-based attacks. This implementation leverages Password4j's SCrypt
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
 * // Using default SCrypt settings (recommended)
 * PasswordEncoder encoder = new ScryptPassword4jPasswordEncoder();
 *
 * // Using custom SCrypt configuration
 * PasswordEncoder customEncoder = new ScryptPassword4jPasswordEncoder(
 *     ScryptFunction.getInstance(32768, 8, 1, 32));
 * }</pre>
 *
 * @author Mehrdad Bozorgmehr
 * @since 7.0
 * @see ScryptFunction
 * @see AlgorithmFinder#getScryptInstance()
 */
public class ScryptPassword4jPasswordEncoder extends Password4jPasswordEncoder {

	/**
	 * Constructs an SCrypt password encoder using the default SCrypt configuration from
	 * Password4j's AlgorithmFinder.
	 */
	public ScryptPassword4jPasswordEncoder() {
		super(AlgorithmFinder.getScryptInstance());
	}

	/**
	 * Constructs an SCrypt password encoder with a custom SCrypt function.
	 * @param scryptFunction the SCrypt function to use for encoding passwords, must not
	 * be null
	 * @throws IllegalArgumentException if scryptFunction is null
	 */
	public ScryptPassword4jPasswordEncoder(ScryptFunction scryptFunction) {
		super(scryptFunction);
	}

}
