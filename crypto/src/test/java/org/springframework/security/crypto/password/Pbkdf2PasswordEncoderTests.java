/*
 * Copyright 2002-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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

public class Pbkdf2PasswordEncoderTests {
	private Pbkdf2PasswordEncoder encoder = new Pbkdf2PasswordEncoder("secret");

	@Test
	public void matches() {
		String result = this.encoder.encode("password");
		assertThat(result.equals("password")).isFalse();
		assertThat(this.encoder.matches("password", result)).isTrue();
	}

	@Test
	public void matchesLengthChecked() {
		String result = this.encoder.encode("password");
		assertThat(this.encoder.matches("password",
				result.substring(0, result.length() - 2))).isFalse();
	}

	@Test
	public void notMatches() {
		String result = this.encoder.encode("password");
		assertThat(this.encoder.matches("bogus", result)).isFalse();
	}

	@Test
	public void encodeSamePasswordMultipleTimesDiffers() {
		String password = "password";
		String encodeFirst = this.encoder.encode(password);
		String encodeSecond = this.encoder.encode(password);
		assertThat(encodeFirst).isNotEqualTo(encodeSecond);
	}

	/**
	 * Used to find the iteration count that takes .5 seconds.
	 */
	public void findDefaultIterationCount() {
		// warm up
		run(180000, 10);
		// find the default
		run(165000, 10);
	}

	private void run(int iterations, int count) {
		long HALF_SECOND = 500L;
		long avg = 0;
		while (avg < HALF_SECOND) {
			iterations += 10000;
			Pbkdf2PasswordEncoder encoder = new Pbkdf2PasswordEncoder("", iterations,
					256);
			String encoded = encoder.encode("password");
			System.out.println("Trying " + iterations);
			long start = System.currentTimeMillis();
			for (int i = 0; i < count; i++) {
				encoder.matches("password", encoded);
			}
			long end = System.currentTimeMillis();
			long diff = end - start;
			avg = diff / count;
			System.out.println("Avgerage " + avg);
		}
		System.out.println("Iterations " + iterations);
	}
}