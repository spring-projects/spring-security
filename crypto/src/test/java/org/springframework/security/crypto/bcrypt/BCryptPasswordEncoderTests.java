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

package org.springframework.security.crypto.bcrypt;

import java.security.SecureRandom;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.crypto.password.AbstractPasswordEncoderValidationTests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * @author Dave Syer
 *
 */
public class BCryptPasswordEncoderTests extends AbstractPasswordEncoderValidationTests {

	@BeforeEach
	void setup() {
		setEncoder(new BCryptPasswordEncoder());
	}

	@Test
	// gh-5548
	public void emptyRawPasswordDoesNotMatchPassword() {
		String result = getEncoder().encode("password");
		assertThat(getEncoder().matches("", result)).isFalse();
	}

	@Test
	public void $2yMatches() {
		// $2y is default version
		String result = getEncoder().encode("password");
		assertThat(result.equals("password")).isFalse();
		assertThat(getEncoder().matches("password", result)).isTrue();
	}

	@Test
	public void $2aMatches() {
		String result = getEncoder().encode("password");
		assertThat(result.equals("password")).isFalse();
		assertThat(getEncoder().matches("password", result)).isTrue();
	}

	@Test
	public void $2bMatches() {
		setEncoder(new BCryptPasswordEncoder(BCryptPasswordEncoder.BCryptVersion.$2B));
		String result = getEncoder().encode("password");
		assertThat(result.equals("password")).isFalse();
		assertThat(getEncoder().matches("password", result)).isTrue();
	}

	@Test
	public void $2yUnicode() {
		// $2y is default version
		String result = getEncoder().encode("passw\u9292rd");
		assertThat(getEncoder().matches("pass\u9292\u9292rd", result)).isFalse();
		assertThat(getEncoder().matches("passw\u9292rd", result)).isTrue();
	}

	@Test
	public void $2aUnicode() {
		setEncoder(new BCryptPasswordEncoder(BCryptPasswordEncoder.BCryptVersion.$2A));
		String result = getEncoder().encode("passw\u9292rd");
		assertThat(getEncoder().matches("pass\u9292\u9292rd", result)).isFalse();
		assertThat(getEncoder().matches("passw\u9292rd", result)).isTrue();
	}

	@Test
	public void $2bUnicode() {
		setEncoder(new BCryptPasswordEncoder(BCryptPasswordEncoder.BCryptVersion.$2B));
		String result = getEncoder().encode("passw\u9292rd");
		assertThat(getEncoder().matches("pass\u9292\u9292rd", result)).isFalse();
		assertThat(getEncoder().matches("passw\u9292rd", result)).isTrue();
	}

	@Test
	public void $2yNotMatches() {
		// $2y is default version
		String result = getEncoder().encode("password");
		assertThat(getEncoder().matches("bogus", result)).isFalse();
	}

	@Test
	public void $2aNotMatches() {
		setEncoder(new BCryptPasswordEncoder(BCryptPasswordEncoder.BCryptVersion.$2A));
		String result = getEncoder().encode("password");
		assertThat(getEncoder().matches("bogus", result)).isFalse();
	}

	@Test
	public void $2bNotMatches() {
		setEncoder(new BCryptPasswordEncoder(BCryptPasswordEncoder.BCryptVersion.$2B));
		String result = getEncoder().encode("password");
		assertThat(getEncoder().matches("bogus", result)).isFalse();
	}

	@Test
	public void $2yCustomStrength() {
		setEncoder(new BCryptPasswordEncoder(8));
		String result = getEncoder().encode("password");
		assertThat(getEncoder().matches("password", result)).isTrue();
	}

	@Test
	public void $2aCustomStrength() {
		setEncoder(new BCryptPasswordEncoder(BCryptPasswordEncoder.BCryptVersion.$2A, 8));
		String result = getEncoder().encode("password");
		assertThat(getEncoder().matches("password", result)).isTrue();
	}

	@Test
	public void $2bCustomStrength() {
		setEncoder(new BCryptPasswordEncoder(BCryptPasswordEncoder.BCryptVersion.$2B, 8));
		String result = getEncoder().encode("password");
		assertThat(getEncoder().matches("password", result)).isTrue();
	}

	@Test
	public void badLowCustomStrength() {
		assertThatIllegalArgumentException().isThrownBy(() -> new BCryptPasswordEncoder(3));
	}

	@Test
	public void badHighCustomStrength() {
		assertThatIllegalArgumentException().isThrownBy(() -> new BCryptPasswordEncoder(32));
	}

	@Test
	public void customRandom() {
		setEncoder(new BCryptPasswordEncoder(8, new SecureRandom()));
		String result = getEncoder().encode("password");
		assertThat(getEncoder().matches("password", result)).isTrue();
	}

	@Test
	public void doesntMatchNullEncodedValue() {
		setEncoder(new BCryptPasswordEncoder());
		assertThat(getEncoder().matches("password", null)).isFalse();
	}

	@Test
	public void doesntMatchEmptyEncodedValue() {
		assertThat(getEncoder().matches("password", "")).isFalse();
	}

	@Test
	public void doesntMatchBogusEncodedValue() {
		assertThat(getEncoder().matches("password", "012345678901234567890123456789")).isFalse();
	}

	@Test
	public void upgradeFromLowerStrength() {
		BCryptPasswordEncoder weakEncoder = new BCryptPasswordEncoder(5);
		BCryptPasswordEncoder strongEncoder = new BCryptPasswordEncoder(15);
		String weakPassword = weakEncoder.encode("password");
		String strongPassword = strongEncoder.encode("password");
		assertThat(weakEncoder.upgradeEncoding(strongPassword)).isFalse();
		assertThat(strongEncoder.upgradeEncoding(weakPassword)).isTrue();
	}

	/**
	 * @see <a href=
	 * "https://github.com/spring-projects/spring-security/pull/7042#issuecomment-506755496">https://github.com/spring-projects/spring-security/pull/7042#issuecomment-506755496</a>
	 */
	@Test
	public void upgradeFromNullOrEmpty() {
		assertThat(getEncoder().upgradeEncoding(null)).isFalse();
		assertThat(getEncoder().upgradeEncoding("")).isFalse();
	}

	/**
	 * @see <a href=
	 * "https://github.com/spring-projects/spring-security/pull/7042#issuecomment-506755496">https://github.com/spring-projects/spring-security/pull/7042#issuecomment-506755496</a>
	 */
	@Test
	public void upgradeFromNonBCrypt() {
		assertThatIllegalArgumentException().isThrownBy(() -> getEncoder().upgradeEncoding("not-a-bcrypt-password"));
	}

	@Test
	public void upgradeWhenNoRoundsThenTrue() {
		assertThat(getEncoder().upgradeEncoding("$2a$00$9N8N35BVs5TLqGL3pspAte5OWWA2a2aZIs.EGp7At7txYakFERMue"))
			.isTrue();
	}

	@Test
	public void checkWhenNoRoundsThenTrue() {
		assertThat(getEncoder().matches("password", "$2a$00$9N8N35BVs5TLqGL3pspAte5OWWA2a2aZIs.EGp7At7txYakFERMue"))
			.isTrue();
		assertThat(getEncoder().matches("wrong", "$2a$00$9N8N35BVs5TLqGL3pspAte5OWWA2a2aZIs.EGp7At7txYakFERMue"))
			.isFalse();
	}

	@Test
	public void encodeWhenPasswordOverMaxLengthThenThrowIllegalArgumentException() {
		String password72chars = "123456789012345678901234567890123456789012345678901234567890123456789012";
		getEncoder().encode(password72chars);

		String password73chars = password72chars + "3";
		assertThatIllegalArgumentException().isThrownBy(() -> getEncoder().encode(password73chars));
	}

	@Test
	public void matchesWhenPasswordOverMaxLengthThenAllowToMatch() {
		String password71chars = "12345678901234567890123456789012345678901234567890123456789012345678901";
		String encodedPassword71chars = "$2a$10$jx3x2FaF.iX5QZ9i3O424Os2Ou5P5JrnedmWYHuDyX8JKA4Unp4xq";
		assertThat(getEncoder().matches(password71chars, encodedPassword71chars)).isTrue();

		String password72chars = password71chars + "2";
		String encodedPassword72chars = "$2a$10$oXYO6/UvbsH5rQEraBkl6uheccBqdB3n.RaWbrimog9hS2GX4lo/O";
		assertThat(getEncoder().matches(password72chars, encodedPassword72chars)).isTrue();

		// Max length is 72 bytes, however, we need to ensure backwards compatibility
		// for previously encoded passwords that are greater than 72 bytes and allow the
		// match to be performed.
		String password73chars = password72chars + "3";
		String encodedPassword73chars = "$2a$10$1l9.kvQTsqNLiCYFqmKtQOHkp.BrgIrwsnTzWo9jdbQRbuBYQ/AVK";
		assertThat(getEncoder().matches(password73chars, encodedPassword73chars)).isTrue();
	}

}
