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

package org.springframework.security.crypto.assertions;

import java.util.Objects;
import java.util.function.Supplier;

import org.assertj.core.api.AbstractObjectAssert;

/**
 * AssertJ assertion for {@link Supplier}&lt;{@link String}&gt;, supporting
 * decryption-related checks such as {@link #doesNotDecryptTo(String)}.
 */
public final class CryptoStringAssert extends AbstractObjectAssert<CryptoStringAssert, Supplier<String>> {

	CryptoStringAssert(Supplier<String> actual) {
		super(actual, CryptoStringAssert.class);
	}

	/**
	 * Asserts that either the supplier throws an exception when invoked, or the value it
	 * returns is not equal to the given string. Use this to assert that a decryption
	 * attempt does not yield a specific plaintext (e.g. wrong key or tampered
	 * ciphertext).
	 * @param expected the value that the supplier must not return
	 * @return this assertion for chaining
	 */
	public CryptoStringAssert doesNotDecryptTo(String expected) {
		isNotNull();
		try {
			String result = this.actual.get();
			if (Objects.equals(result, expected)) {
				failWithMessage("Expected supplier not to return <%s> but it did", expected);
			}
		}
		catch (Exception ex) {
			// Exception thrown: supplier does not "decrypt to" the expected value
		}
		return this;
	}

}
