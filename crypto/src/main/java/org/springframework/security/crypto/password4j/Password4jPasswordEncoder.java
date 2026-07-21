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

import com.password4j.HashBuilder;
import com.password4j.HashChecker;
import com.password4j.HashingFunction;
import com.password4j.Password;
import org.jspecify.annotations.Nullable;

import org.springframework.security.crypto.password.AbstractValidatingPasswordEncoder;
import org.springframework.util.Assert;

/**
 * Abstract base class for Password4j-based password encoders. This class provides the
 * common functionality for password encoding and verification using the Password4j
 * library.
 *
 * <p>
 * This class is package-private and should not be used directly. Instead, use the
 * specific public subclasses that support verified hashing algorithms such as BCrypt,
 * Argon2, and SCrypt implementations.
 * </p>
 *
 * <p>
 * This implementation is thread-safe and can be shared across multiple threads.
 * </p>
 *
 * @author Mehrdad Bozorgmehr
 * @author Andrey Litvitski
 * @since 7.0
 */
abstract class Password4jPasswordEncoder extends AbstractValidatingPasswordEncoder {

	private final HashingFunction hashingFunction;

	@Nullable private final String pepper;

	/**
	 * Constructs a Password4j password encoder with the specified hashing function. This
	 * constructor is package-private and intended for use by subclasses only.
	 * @param hashingFunction the hashing function to use for encoding passwords, must not
	 * be null
	 * @throws IllegalArgumentException if hashingFunction is null
	 */
	Password4jPasswordEncoder(HashingFunction hashingFunction) {
		this(hashingFunction, null);
	}

	/**
	 * Constructs a Password4j password encoder with the specified hashing function and a
	 * pepper. This constructor is package-private and intended for use by subclasses
	 * only.
	 * @param hashingFunction the hashing function to use for encoding passwords, must not
	 * be null
	 * @param pepper the pepper to be used in the hashing process. If null, no pepper will
	 * be applied.
	 * @throws IllegalArgumentException if hashingFunction is null
	 */
	Password4jPasswordEncoder(HashingFunction hashingFunction, @Nullable String pepper) {
		Assert.notNull(hashingFunction, "hashingFunction cannot be null");
		this.hashingFunction = hashingFunction;
		this.pepper = pepper;
	}

	@Override
	protected String encodeNonNullPassword(String rawPassword) {
		HashBuilder hashBuilder = Password.hash(rawPassword);
		if (this.pepper != null) {
			hashBuilder = hashBuilder.addPepper(this.pepper);
		}
		return hashBuilder.with(this.hashingFunction).getResult();
	}

	@Override
	protected boolean matchesNonNull(String rawPassword, String encodedPassword) {
		HashChecker hashChecker = Password.check(rawPassword, encodedPassword);
		if (this.pepper != null) {
			hashChecker = hashChecker.addPepper(this.pepper);
		}
		return hashChecker.with(this.hashingFunction);
	}

	@Override
	protected boolean upgradeEncodingNonNull(String encodedPassword) {
		// Password4j handles upgrade detection internally for most algorithms
		// For now, we'll return false to maintain existing behavior
		return false;
	}

}
