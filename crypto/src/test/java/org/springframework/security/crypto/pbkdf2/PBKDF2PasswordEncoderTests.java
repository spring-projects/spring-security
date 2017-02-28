/*
 * Copyright 2011-2017 the original author or authors.
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
package org.springframework.security.crypto.pbkdf2;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.crypto.codec.Codecs;

import java.security.NoSuchAlgorithmException;

import static org.assertj.core.api.Assertions.assertThat;

public class PBKDF2PasswordEncoderTests {
	private static final String PASS = "quick brown fox jumps over the lazy dog";
	private static final String GOOD = "ec87602c076fc532689027d236ded368d000f70216e9c4338d6e5d0d98295190ff1b5e554b5d9542";
	private static final String CAFE = "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe";

	private PBKDF2PasswordEncoder encoder;

	@Before
	public void setUp() throws Exception {
		encoder = new PBKDF2PasswordEncoder();
	}

	@Test
	public void shouldMatch() throws Exception {
		assertThat(encoder.matches(PASS, GOOD))
			.isTrue();
	}

	@Test
	public void shouldNotMatch() throws Exception {
		assertThat(encoder.matches(PASS, CAFE))
			.isFalse();
	}

	@Test
	public void shouldGenerateUniqueFootprint() throws Exception {
		String encoded = encoder.encode(PASS);
		assertThat(encoder.matches(PASS, encoded))
			.isTrue();
		assertThat(encoded).isNotEqualToIgnoringCase(GOOD);
	}

	@Test
	public void shouldHaveTheGoodLengthInHexadecimal() throws Exception {
		String encoded = encoder.encode(PASS);
		int saltLength = 8;
		int hashLength = 32;
		assertThat(encoded).hasSize(hexaLength(saltLength + hashLength));
	}

	private int hexaLength(int lengthInBytes) {
		return lengthInBytes * 2;
	}

	@Test
	public void shouldHaveTheGoodLengthInBase64() throws Exception {
		int saltLength = 8;
		int hashLength = 32;
		encoder = new PBKDF2PasswordEncoder(saltLength, hashLength, PBKDF2PasswordEncoder.DEFAULT_ITERATION_COUNT, new PBKDF2(PBKDF2.WITH_HMAC_SHA1), Codecs.base64());
		String encoded = encoder.encode(PASS);
		assertThat(encoded).hasSize(base64Length(saltLength + hashLength));
	}

	private int base64Length(int lengthInBytes) {
		double length = lengthInBytes * 4.0 / 3.0;
		return ((int) (length / 4)) * 4 + 4;
	}

	@Test
	public void hmacSHA256IsNotSupportedBeforeJava8() throws Exception {
		try {
			assertThat(new PBKDF2(PBKDF2.WITH_HMAC_SHA256)).isNotNull(); // Only true on JDK 8 and later
			assertThat(Double.valueOf(System.getProperty("java.specification.version")))
				.isGreaterThanOrEqualTo(1.8);
		} catch (IllegalArgumentException exception) {
			assertThat(exception)
				.hasMessage("Could not create PBKDF2 instance PBKDF2WithHmacSHA256")
				.hasCauseInstanceOf(NoSuchAlgorithmException.class);
			assertThat(Double.valueOf(System.getProperty("java.specification.version")))
				.isLessThan(1.8);
		}
	}
}
