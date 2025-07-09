/*
 * Copyright 2002-2025 the original author or authors.
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

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A base class for other tests to perform validation of the arguments to
 * {@link PasswordEncoder} instances in a consistent way.
 *
 * @author Rob Winch
 */
public abstract class AbstractPasswordEncoderValidationTests {

	private PasswordEncoder encoder;

	protected void setEncoder(PasswordEncoder encoder) {
		this.encoder = encoder;
	}

	protected <T extends PasswordEncoder> T getEncoder(Class<T> clazz) {
		return getEncoder();
	}

	protected <T extends PasswordEncoder> T getEncoder() {
		return (T) this.encoder;
	}

	@Test
	void encodeWhenNullThenNull() {
		assertThat(this.encoder.encode(null)).isNull();
	}

	@Test
	void matchesWhenEncodedPasswordNullThenFalse() {
		assertThat(this.encoder.matches("raw", null)).isFalse();
	}

	@Test
	void matchesWhenEncodedPasswordEmptyThenFalse() {
		assertThat(this.encoder.matches("raw", "")).isFalse();
	}

	@Test
	void matchesWhenRawPasswordNullThenFalse() {
		assertThat(this.encoder.matches(null, this.encoder.encode("password"))).isFalse();
	}

	@Test
	void matchesWhenRawPasswordEmptyThenFalse() {
		assertThat(this.encoder.matches("", this.encoder.encode("password"))).isFalse();
	}

}
