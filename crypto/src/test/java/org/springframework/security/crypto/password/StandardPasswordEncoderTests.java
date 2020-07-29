/*
 * Copyright 2002-2016 the original author or authors.
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

@SuppressWarnings("deprecation")
public class StandardPasswordEncoderTests {

	private StandardPasswordEncoder encoder = new StandardPasswordEncoder("secret");

	@Test
	public void matches() {
		String result = this.encoder.encode("password");
		assertThat(result).isNotEqualTo("password");
		assertThat(this.encoder.matches("password", result)).isTrue();
	}

	@Test
	public void matchesLengthChecked() {
		String result = this.encoder.encode("password");
		assertThat(this.encoder.matches("password", result.substring(0, result.length() - 2))).isFalse();
	}

	@Test
	public void notMatches() {
		String result = this.encoder.encode("password");
		assertThat(this.encoder.matches("bogus", result)).isFalse();
	}

}
