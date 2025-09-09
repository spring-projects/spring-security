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
import com.password4j.BcryptFunction;

/**
 * Implementation of {@link org.springframework.security.crypto.password.PasswordEncoder}
 * that uses the Password4j library with BCrypt hashing algorithm.
 *
 * <p>
 * BCrypt is a well-established password hashing algorithm that includes built-in salt
 * generation and is resistant to rainbow table attacks. This implementation leverages
 * Password4j's BCrypt support which properly includes the salt in the output hash.
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
 * // Using default BCrypt settings (recommended)
 * PasswordEncoder encoder = new BcryptPassword4jPasswordEncoder();
 *
 * // Using custom round count
 * PasswordEncoder customEncoder = new BcryptPassword4jPasswordEncoder(BcryptFunction.getInstance(12));
 * }</pre>
 *
 * @author Mehrdad Bozorgmehr
 * @since 7.0
 * @see BcryptFunction
 * @see AlgorithmFinder#getBcryptInstance()
 */
public class BcryptPassword4jPasswordEncoder extends Password4jPasswordEncoder {

	/**
	 * Constructs a BCrypt password encoder using the default BCrypt configuration from
	 * Password4j's AlgorithmFinder.
	 */
	public BcryptPassword4jPasswordEncoder() {
		super(AlgorithmFinder.getBcryptInstance());
	}

	/**
	 * Constructs a BCrypt password encoder with a custom BCrypt function.
	 * @param bcryptFunction the BCrypt function to use for encoding passwords, must not
	 * be null
	 * @throws IllegalArgumentException if bcryptFunction is null
	 */
	public BcryptPassword4jPasswordEncoder(BcryptFunction bcryptFunction) {
		super(bcryptFunction);
	}

}
