/*
 * Copyright 2002-2017 the original author or authors.
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

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 */
public class PasswordEncoderUtilsTests {

	@Test
	public void equalsWhenDifferentLengthThenFalse() {
		assertThat(PasswordEncoderUtils.equals("abc", "a")).isFalse();
		assertThat(PasswordEncoderUtils.equals("a", "abc")).isFalse();
	}

	@Test
	public void equalsWhenNullAndNotEmtpyThenFalse() {
		assertThat(PasswordEncoderUtils.equals(null, "a")).isFalse();
		assertThat(PasswordEncoderUtils.equals("a", null)).isFalse();
	}

	@Test
	public void equalsWhenNullAndNullThenTrue() {
		assertThat(PasswordEncoderUtils.equals(null, null)).isTrue();
	}

	@Test
	public void equalsWhenNullAndEmptyThenFalse() {
		assertThat(PasswordEncoderUtils.equals(null, "")).isFalse();
		assertThat(PasswordEncoderUtils.equals("", null)).isFalse();
	}

	@Test
	public void equalsWhenNotEmptyAndEmptyThenFalse() {
		assertThat(PasswordEncoderUtils.equals("abc", "")).isFalse();
		assertThat(PasswordEncoderUtils.equals("", "abc")).isFalse();
	}

	@Test
	public void equalsWhenEmtpyAndEmptyThenTrue() {
		assertThat(PasswordEncoderUtils.equals("", "")).isTrue();
	}

	@Test
	public void equalsWhenDifferentCaseThenFalse() {
		assertThat(PasswordEncoderUtils.equals("aBc", "abc")).isFalse();
	}

	@Test
	public void equalsWhenSameThenTrue() {
		assertThat(PasswordEncoderUtils.equals("abcdef", "abcdef")).isTrue();
	}

}
