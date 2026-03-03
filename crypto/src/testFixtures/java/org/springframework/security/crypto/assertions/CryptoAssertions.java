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

import java.util.function.Supplier;

/**
 * AssertJ entry point for crypto-related assertions. Use {@link #assertThat(Supplier)} to
 * assert on a {@link Supplier}&lt;{@link String}&gt; (e.g. a decryption lambda).
 * <p>
 * Example: <pre>
 * assertThat(() -&gt; encryptor.decrypt(ciphertext)).doesNotDecryptTo("plaintext");
 * </pre>
 */
public final class CryptoAssertions {

	private CryptoAssertions() {
	}

	/**
	 * Create assertions for the given supplier (e.g. a decryption expression).
	 * @param actual the supplier to assert on
	 * @return assertion object with methods like
	 * {@link CryptoStringAssert#doesNotDecryptTo(String)}
	 */
	public static CryptoStringAssert assertThat(Supplier<String> actual) {
		return new CryptoStringAssert(actual);
	}

}
