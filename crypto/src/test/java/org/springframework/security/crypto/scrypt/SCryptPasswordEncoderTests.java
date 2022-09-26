/*
 * Copyright 2002-2022 the original author or authors.
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

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * @author Shazin Sadakath
 *
 */
public class SCryptPasswordEncoderTests {

	@Test
	public void matches() {
		SCryptPasswordEncoder encoder = SCryptPasswordEncoder.defaultsForSpringSecurity_v4_1();
		String result = encoder.encode("password");
		assertThat(result).isNotEqualTo("password");
		assertThat(encoder.matches("password", result)).isTrue();
	}

	@Test
	public void unicode() {
		SCryptPasswordEncoder encoder = SCryptPasswordEncoder.defaultsForSpringSecurity_v4_1();
		String result = encoder.encode("passw\u9292rd");
		assertThat(encoder.matches("pass\u9292\u9292rd", result)).isFalse();
		assertThat(encoder.matches("passw\u9292rd", result)).isTrue();
	}

	@Test
	public void notMatches() {
		SCryptPasswordEncoder encoder = SCryptPasswordEncoder.defaultsForSpringSecurity_v4_1();
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
		SCryptPasswordEncoder encoder = SCryptPasswordEncoder.defaultsForSpringSecurity_v4_1();
		String password = "secret";
		assertThat(encoder.encode(password)).isNotEqualTo(encoder.encode(password));
	}

	@Test
	public void samePasswordWithDifferentParams() {
		SCryptPasswordEncoder oldEncoder = SCryptPasswordEncoder.defaultsForSpringSecurity_v4_1();
		SCryptPasswordEncoder newEncoder = SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8();
		String password = "secret";
		String oldEncodedPassword = oldEncoder.encode(password);
		assertThat(newEncoder.matches(password, oldEncodedPassword)).isTrue();
	}

	@Test
	public void doesntMatchNullEncodedValue() {
		SCryptPasswordEncoder encoder = SCryptPasswordEncoder.defaultsForSpringSecurity_v4_1();
		assertThat(encoder.matches("password", null)).isFalse();
	}

	@Test
	public void doesntMatchEmptyEncodedValue() {
		SCryptPasswordEncoder encoder = SCryptPasswordEncoder.defaultsForSpringSecurity_v4_1();
		assertThat(encoder.matches("password", "")).isFalse();
	}

	@Test
	public void doesntMatchBogusEncodedValue() {
		SCryptPasswordEncoder encoder = SCryptPasswordEncoder.defaultsForSpringSecurity_v4_1();
		assertThat(encoder.matches("password", "012345678901234567890123456789")).isFalse();
	}

	@Test
	public void invalidCpuCostParameter() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new SCryptPasswordEncoder(Integer.MIN_VALUE, 16, 2, 32, 16));
	}

	@Test
	public void invalidMemoryCostParameter() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new SCryptPasswordEncoder(2, Integer.MAX_VALUE, 2, 32, 16));
	}

	@Test
	public void invalidParallelizationParameter() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new SCryptPasswordEncoder(2, 8, Integer.MAX_VALUE, 32, 16));
	}

	@Test
	public void invalidSaltLengthParameter() {
		assertThatIllegalArgumentException().isThrownBy(() -> new SCryptPasswordEncoder(2, 8, 1, 16, -1));
	}

	@Test
	public void invalidKeyLengthParameter() {
		assertThatIllegalArgumentException().isThrownBy(() -> new SCryptPasswordEncoder(2, 8, 1, -1, 16));
	}

	@Test
	public void upgradeEncodingWhenNullThenFalse() {
		SCryptPasswordEncoder encoder = SCryptPasswordEncoder.defaultsForSpringSecurity_v4_1();
		assertThat(encoder.upgradeEncoding(null)).isFalse();
	}

	@Test
	public void upgradeEncodingWhenEmptyThenFalse() {
		SCryptPasswordEncoder encoder = SCryptPasswordEncoder.defaultsForSpringSecurity_v4_1();
		assertThat(encoder.upgradeEncoding("")).isFalse();
	}

	@Test
	public void upgradeEncodingWhenSameEncoderThenFalse() {
		SCryptPasswordEncoder encoder = SCryptPasswordEncoder.defaultsForSpringSecurity_v4_1();
		String encoded = encoder.encode("password");
		assertThat(encoder.upgradeEncoding(encoded)).isFalse();
	}

	@Test
	public void upgradeEncodingWhenWeakerToStrongerThenFalse() {
		SCryptPasswordEncoder weakEncoder = new SCryptPasswordEncoder((int) Math.pow(2, 10), 4, 1, 32, 64);
		SCryptPasswordEncoder strongEncoder = new SCryptPasswordEncoder((int) Math.pow(2, 16), 8, 1, 32, 64);
		String weakPassword = weakEncoder.encode("password");
		String strongPassword = strongEncoder.encode("password");
		assertThat(weakEncoder.upgradeEncoding(strongPassword)).isFalse();
	}

	@Test
	public void upgradeEncodingWhenStrongerToWeakerThenTrue() {
		SCryptPasswordEncoder weakEncoder = new SCryptPasswordEncoder((int) Math.pow(2, 10), 4, 1, 32, 64);
		SCryptPasswordEncoder strongEncoder = new SCryptPasswordEncoder((int) Math.pow(2, 16), 8, 1, 32, 64);
		String weakPassword = weakEncoder.encode("password");
		String strongPassword = strongEncoder.encode("password");
		assertThat(strongEncoder.upgradeEncoding(weakPassword)).isTrue();
	}

	@Test
	public void upgradeEncodingWhenInvalidInputThenException() {
		assertThatIllegalArgumentException().isThrownBy(
				() -> SCryptPasswordEncoder.defaultsForSpringSecurity_v4_1().upgradeEncoding("not-a-scrypt-password"));
	}

}
