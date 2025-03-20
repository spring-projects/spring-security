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

import java.security.SecureRandom;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * @author Dave Syer
 *
 */
public class BCryptPasswordEncoderTests {

	@Test
	// gh-5548
	public void emptyRawPasswordDoesNotMatchPassword() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		String result = encoder.encode("password");
		assertThat(encoder.matches("", result)).isFalse();
	}

	@Test
	public void $2yMatches() {
		// $2y is default version
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		String result = encoder.encode("password");
		assertThat(result.equals("password")).isFalse();
		assertThat(encoder.matches("password", result)).isTrue();
	}

	@Test
	public void $2aMatches() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(BCryptPasswordEncoder.BCryptVersion.$2A);
		String result = encoder.encode("password");
		assertThat(result.equals("password")).isFalse();
		assertThat(encoder.matches("password", result)).isTrue();
	}

	@Test
	public void $2bMatches() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(BCryptPasswordEncoder.BCryptVersion.$2B);
		String result = encoder.encode("password");
		assertThat(result.equals("password")).isFalse();
		assertThat(encoder.matches("password", result)).isTrue();
	}

	@Test
	public void $2yUnicode() {
		// $2y is default version
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		String result = encoder.encode("passw\u9292rd");
		assertThat(encoder.matches("pass\u9292\u9292rd", result)).isFalse();
		assertThat(encoder.matches("passw\u9292rd", result)).isTrue();
	}

	@Test
	public void $2aUnicode() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(BCryptPasswordEncoder.BCryptVersion.$2A);
		String result = encoder.encode("passw\u9292rd");
		assertThat(encoder.matches("pass\u9292\u9292rd", result)).isFalse();
		assertThat(encoder.matches("passw\u9292rd", result)).isTrue();
	}

	@Test
	public void $2bUnicode() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(BCryptPasswordEncoder.BCryptVersion.$2B);
		String result = encoder.encode("passw\u9292rd");
		assertThat(encoder.matches("pass\u9292\u9292rd", result)).isFalse();
		assertThat(encoder.matches("passw\u9292rd", result)).isTrue();
	}

	@Test
	public void $2yNotMatches() {
		// $2y is default version
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		String result = encoder.encode("password");
		assertThat(encoder.matches("bogus", result)).isFalse();
	}

	@Test
	public void $2aNotMatches() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(BCryptPasswordEncoder.BCryptVersion.$2A);
		String result = encoder.encode("password");
		assertThat(encoder.matches("bogus", result)).isFalse();
	}

	@Test
	public void $2bNotMatches() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(BCryptPasswordEncoder.BCryptVersion.$2B);
		String result = encoder.encode("password");
		assertThat(encoder.matches("bogus", result)).isFalse();
	}

	@Test
	public void $2yCustomStrength() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(8);
		String result = encoder.encode("password");
		assertThat(encoder.matches("password", result)).isTrue();
	}

	@Test
	public void $2aCustomStrength() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(BCryptPasswordEncoder.BCryptVersion.$2A, 8);
		String result = encoder.encode("password");
		assertThat(encoder.matches("password", result)).isTrue();
	}

	@Test
	public void $2bCustomStrength() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(BCryptPasswordEncoder.BCryptVersion.$2B, 8);
		String result = encoder.encode("password");
		assertThat(encoder.matches("password", result)).isTrue();
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
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		assertThat(encoder.upgradeEncoding(null)).isFalse();
		assertThat(encoder.upgradeEncoding("")).isFalse();
	}

	/**
	 * @see <a href=
	 * "https://github.com/spring-projects/spring-security/pull/7042#issuecomment-506755496">https://github.com/spring-projects/spring-security/pull/7042#issuecomment-506755496</a>
	 */
	@Test
	public void upgradeFromNonBCrypt() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		assertThatIllegalArgumentException().isThrownBy(() -> encoder.upgradeEncoding("not-a-bcrypt-password"));
	}

	@Test
	public void encodeNullRawPassword() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		assertThatIllegalArgumentException().isThrownBy(() -> encoder.encode(null));
	}

	@Test
	public void matchNullRawPassword() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		assertThatIllegalArgumentException().isThrownBy(() -> encoder.matches(null, "does-not-matter"));
	}

	@Test
	public void upgradeWhenNoRoundsThenTrue() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		assertThat(encoder.upgradeEncoding("$2a$00$9N8N35BVs5TLqGL3pspAte5OWWA2a2aZIs.EGp7At7txYakFERMue")).isTrue();
	}

	@Test
	public void checkWhenNoRoundsThenTrue() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		assertThat(encoder.matches("password", "$2a$00$9N8N35BVs5TLqGL3pspAte5OWWA2a2aZIs.EGp7At7txYakFERMue"))
			.isTrue();
		assertThat(encoder.matches("wrong", "$2a$00$9N8N35BVs5TLqGL3pspAte5OWWA2a2aZIs.EGp7At7txYakFERMue")).isFalse();
	}

	@Test
	public void enforcePasswordLength() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		String password72chars = "123456789012345678901234567890123456789012345678901234567890123456789012";
		assertThat(encoder.matches(password72chars, encoder.encode(password72chars))).isTrue();
		String password73chars = password72chars.concat("a");
		assertThatIllegalArgumentException()
			.isThrownBy(() -> encoder.matches(password73chars, encoder.encode(password73chars)));
	}

}
