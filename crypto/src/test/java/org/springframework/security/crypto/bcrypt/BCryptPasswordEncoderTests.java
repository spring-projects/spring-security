/*
 * Copyright 2002-2011 the original author or authors.
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

import org.junit.Test;

import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Dave Syer
 *
 */
public class BCryptPasswordEncoderTests {

	@Test
	public void matches() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		String result = encoder.encode("password");
		assertThat(result.equals("password")).isFalse();
		assertThat(encoder.matches("password", result)).isTrue();
	}

	@Test
	public void unicode() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		String result = encoder.encode("passw\u9292rd");
		assertThat(encoder.matches("pass\u9292\u9292rd", result)).isFalse();
		assertThat(encoder.matches("passw\u9292rd", result)).isTrue();
	}

	@Test
	public void notMatches() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		String result = encoder.encode("password");
		assertThat(encoder.matches("bogus", result)).isFalse();
	}

	@Test
	public void customStrength() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(8);
		String result = encoder.encode("password");
		assertThat(encoder.matches("password", result)).isTrue();
	}

	@Test(expected = IllegalArgumentException.class)
	public void badLowCustomStrength() {
		new BCryptPasswordEncoder(3);
	}

	@Test(expected = IllegalArgumentException.class)
	public void badHighCustomStrength() {
		new BCryptPasswordEncoder(32);
	}

	@Test
	public void customRandom() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(8, new SecureRandom());
		String result = encoder.encode("password");
		assertThat(encoder.matches("password", result)).isTrue();
	}

	@Test
	public void doesntMatchNullEncodedValue() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		assertThat(encoder.matches("password", null)).isFalse();
	}

	@Test
	public void doesntMatchEmptyEncodedValue() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		assertThat(encoder.matches("password", "")).isFalse();
	}

	@Test
	public void doesntMatchBogusEncodedValue() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		assertThat(encoder.matches("password", "012345678901234567890123456789")).isFalse();
	}

	@Test(expected = IllegalArgumentException.class)
	public void encodeNullRawPassword() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		encoder.encode(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void matchNullRawPassword() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		encoder.matches(null, "does-not-matter");
	}
}
