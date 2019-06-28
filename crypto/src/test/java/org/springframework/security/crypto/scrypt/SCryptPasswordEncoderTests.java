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
package org.springframework.security.crypto.scrypt;

import static org.assertj.core.api.Assertions.*;

import org.junit.Test;

/**
 * @author Shazin Sadakath
 *
 */
public class SCryptPasswordEncoderTests {

	@Test
	public void matches() {
		SCryptPasswordEncoder encoder = new SCryptPasswordEncoder();
		String result = encoder.encode("password");
		assertThat(result).isNotEqualTo("password");
		assertThat(encoder.matches("password", result)).isTrue();
	}

	@Test
	public void unicode() {
		SCryptPasswordEncoder encoder = new SCryptPasswordEncoder();
		String result = encoder.encode("passw\u9292rd");
		assertThat(encoder.matches("pass\u9292\u9292rd", result)).isFalse();
		assertThat(encoder.matches("passw\u9292rd", result)).isTrue();
	}

	@Test
	public void notMatches() {
		SCryptPasswordEncoder encoder = new SCryptPasswordEncoder();
		String result = encoder.encode("password");
		assertThat(encoder.matches("bogus", result)).isFalse();
	}

	@Test
	public void customParameters() {
		SCryptPasswordEncoder encoder = new SCryptPasswordEncoder(512, 8, 4, 32, 16);
		String result = encoder.encode("password");
		assertThat(result).isNotEqualTo("password");
		assertThat(encoder.matches("password", result)).isTrue();
	}

	@Test
	public void differentPasswordHashes() {
		SCryptPasswordEncoder encoder = new SCryptPasswordEncoder();
		String password = "secret";
		assertThat(encoder.encode(password)).isNotEqualTo(encoder.encode(password));
	}

	@Test
	public void samePasswordWithDifferentParams() {
		SCryptPasswordEncoder oldEncoder = new SCryptPasswordEncoder(16384, 8, 1, 32, 64);
		SCryptPasswordEncoder newEncoder = new SCryptPasswordEncoder();

		String password = "secret";
		String oldEncodedPassword = oldEncoder.encode(password);
		assertThat(newEncoder.matches(password, oldEncodedPassword)).isTrue();
	}

	@Test
	public void doesntMatchNullEncodedValue() {
		SCryptPasswordEncoder encoder = new SCryptPasswordEncoder();
		assertThat(encoder.matches("password", null)).isFalse();
	}

	@Test
	public void doesntMatchEmptyEncodedValue() {
		SCryptPasswordEncoder encoder = new SCryptPasswordEncoder();
		assertThat(encoder.matches("password", "")).isFalse();
	}

	@Test
	public void doesntMatchBogusEncodedValue() {
		SCryptPasswordEncoder encoder = new SCryptPasswordEncoder();
		assertThat(encoder.matches("password", "012345678901234567890123456789")).isFalse();
	}

	@Test(expected = IllegalArgumentException.class)
	public void invalidCpuCostParameter() {
		new SCryptPasswordEncoder(Integer.MIN_VALUE, 16, 2, 32, 16);
	}

	@Test(expected = IllegalArgumentException.class)
	public void invalidMemoryCostParameter() {
		new SCryptPasswordEncoder(2, Integer.MAX_VALUE, 2, 32, 16);
	}

	@Test(expected = IllegalArgumentException.class)
	public void invalidParallelizationParameter() {
		new SCryptPasswordEncoder(2, 8, Integer.MAX_VALUE, 32, 16);
	}

	@Test(expected = IllegalArgumentException.class)
	public void invalidSaltLengthParameter() {
		new SCryptPasswordEncoder(2, 8, 1, 16, -1);
	}

	@Test(expected = IllegalArgumentException.class)
	public void invalidKeyLengthParameter() {
		new SCryptPasswordEncoder(2, 8, 1, -1, 16);
	}

	@Test
	public void upgradeEncoding_nullOrEmptyInput() {
		SCryptPasswordEncoder encoder = new SCryptPasswordEncoder();
		assertThat(encoder.upgradeEncoding(null)).isFalse();
		assertThat(encoder.upgradeEncoding("")).isFalse();
	}

	@Test
	public void upgradeEncoding_sameEncoder() {
		SCryptPasswordEncoder encoder = new SCryptPasswordEncoder();
		String encoded = encoder.encode("password");
		assertThat(encoder.upgradeEncoding(encoded)).isFalse();
	}

	@Test
	public void upgradeEncoding_weakerToStronger() {
		SCryptPasswordEncoder weakEncoder = new SCryptPasswordEncoder((int) Math.pow(2, 10), 4, 1, 32, 64);
		SCryptPasswordEncoder strongEncoder = new SCryptPasswordEncoder((int) Math.pow(2, 16), 8, 1, 32, 64);

		String weakPassword = weakEncoder.encode("password");
		String strongPassword = strongEncoder.encode("password");

		assertThat(strongEncoder.upgradeEncoding(weakPassword)).isTrue();
		assertThat(weakEncoder.upgradeEncoding(strongPassword)).isFalse();
	}

	@Test(expected = IllegalArgumentException.class)
	public void upgradeEncoding_invalidInput() {
		new SCryptPasswordEncoder().upgradeEncoding("not-a-scrypt-password");
	}
}

