/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.crypto.argon2;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Field;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;

/**
 * @author Simeon Macke
 */
@RunWith(MockitoJUnitRunner.class)
public class Argon2PasswordEncoderTests {

	@Mock
	private BytesKeyGenerator keyGeneratorMock;

	private Argon2PasswordEncoder encoder = new Argon2PasswordEncoder();

	@Test
	public void encodeDoesNotEqualPassword() {
		String result = encoder.encode("password");
		assertThat(result).isNotEqualTo("password");
	}

	@Test
	public void encodeWhenEqualPasswordThenMatches() {
		String result = encoder.encode("password");
		assertThat(encoder.matches("password", result)).isTrue();
	}

	@Test
	public void encodeWhenEqualWithUnicodeThenMatches() {
		String result = encoder.encode("passw\u9292rd");
		assertThat(encoder.matches("pass\u9292\u9292rd", result)).isFalse();
		assertThat(encoder.matches("passw\u9292rd", result)).isTrue();
	}

	@Test
	public void encodeWhenNotEqualThenNotMatches() {
		String result = encoder.encode("password");
		assertThat(encoder.matches("bogus", result)).isFalse();
	}

	@Test
	public void encodeWhenEqualPasswordWithCustomParamsThenMatches() {
		encoder = new Argon2PasswordEncoder(20, 64, 4, 256, 4);
		String result = encoder.encode("password");
		assertThat(encoder.matches("password", result)).isTrue();
	}

	@Test
	public void encodeWhenRanTwiceThenResultsNotEqual() {
		String password = "secret";
		assertThat(encoder.encode(password)).isNotEqualTo(encoder.encode(password));
	}

	@Test
	public void encodeWhenRanTwiceWithCustomParamsThenNotEquals() {
		encoder = new Argon2PasswordEncoder(20, 64, 4, 256, 4);
		String password = "secret";
		assertThat(encoder.encode(password)).isNotEqualTo(encoder.encode(password));
	}

	@Test
	public void matchesWhenGeneratedWithDifferentEncoderThenTrue() {
		Argon2PasswordEncoder oldEncoder = new Argon2PasswordEncoder(20, 64, 4, 256, 4);
		Argon2PasswordEncoder newEncoder = new Argon2PasswordEncoder();

		String password = "secret";
		String oldEncodedPassword = oldEncoder.encode(password);
		assertThat(newEncoder.matches(password, oldEncodedPassword)).isTrue();
	}

	@Test
	public void matchesWhenEncodedPassIsNullThenFalse() {
		assertThat(encoder.matches("password", null)).isFalse();
	}

	@Test
	public void matchesWhenEncodedPassIsEmptyThenFalse() {
		assertThat(encoder.matches("password", "")).isFalse();
	}

	@Test
	public void matchesWhenEncodedPassIsBogusThenFalse() {
		assertThat(encoder.matches("password", "012345678901234567890123456789")).isFalse();
	}

	@Test
	public void encodeWhenUsingPredictableSaltThenEqualTestHash() throws Exception {
		injectPredictableSaltGen();

		String hash = encoder.encode("sometestpassword");

		assertThat(hash).isEqualTo(
				"$argon2id$v=19$m=4096,t=3,p=1$QUFBQUFBQUFBQUFBQUFBQQ$hmmTNyJlwbb6HAvFoHFWF+u03fdb0F2qA+39oPlcAqo");
	}

	@Test
	public void encodeWhenUsingPredictableSaltWithCustomParamsThenEqualTestHash() throws Exception {
		encoder = new Argon2PasswordEncoder(16, 32, 4, 512, 5);
		injectPredictableSaltGen();
		String hash = encoder.encode("sometestpassword");

		assertThat(hash).isEqualTo(
				"$argon2id$v=19$m=512,t=5,p=4$QUFBQUFBQUFBQUFBQUFBQQ$PNv4C3K50bz3rmON+LtFpdisD7ePieLNq+l5iUHgc1k");
	}

	@Test
	public void upgradeEncodingWhenSameEncodingThenFalse() {
		String hash = encoder.encode("password");

		assertThat(encoder.upgradeEncoding(hash)).isFalse();
	}

	@Test
	public void upgradeEncodingWhenSameStandardParamsThenFalse() {
		Argon2PasswordEncoder newEncoder = new Argon2PasswordEncoder();

		String hash = encoder.encode("password");

		assertThat(newEncoder.upgradeEncoding(hash)).isFalse();
	}

	@Test
	public void upgradeEncodingWhenSameCustomParamsThenFalse() {
		Argon2PasswordEncoder oldEncoder = new Argon2PasswordEncoder(20, 64, 4, 256, 4);
		Argon2PasswordEncoder newEncoder = new Argon2PasswordEncoder(20, 64, 4, 256, 4);

		String hash = oldEncoder.encode("password");

		assertThat(newEncoder.upgradeEncoding(hash)).isFalse();
	}

	@Test
	public void upgradeEncodingWhenHashHasLowerMemoryThenTrue() {
		Argon2PasswordEncoder oldEncoder = new Argon2PasswordEncoder(20, 64, 4, 256, 4);
		Argon2PasswordEncoder newEncoder = new Argon2PasswordEncoder(20, 64, 4, 512, 4);

		String hash = oldEncoder.encode("password");

		assertThat(newEncoder.upgradeEncoding(hash)).isTrue();
	}

	@Test
	public void upgradeEncodingWhenHashHasLowerIterationsThenTrue() {
		Argon2PasswordEncoder oldEncoder = new Argon2PasswordEncoder(20, 64, 4, 256, 4);
		Argon2PasswordEncoder newEncoder = new Argon2PasswordEncoder(20, 64, 4, 256, 5);

		String hash = oldEncoder.encode("password");

		assertThat(newEncoder.upgradeEncoding(hash)).isTrue();
	}

	@Test
	public void upgradeEncodingWhenHashHasHigherParamsThenFalse() {
		Argon2PasswordEncoder oldEncoder = new Argon2PasswordEncoder(20, 64, 4, 256, 4);
		Argon2PasswordEncoder newEncoder = new Argon2PasswordEncoder(20, 64, 4, 128, 3);

		String hash = oldEncoder.encode("password");

		assertThat(newEncoder.upgradeEncoding(hash)).isFalse();
	}

	@Test
	public void upgradeEncodingWhenEncodedPassIsNullThenFalse() {
		assertThat(encoder.upgradeEncoding(null)).isFalse();
	}

	@Test
	public void upgradeEncodingWhenEncodedPassIsEmptyThenFalse() {
		assertThat(encoder.upgradeEncoding("")).isFalse();
	}

	@Test(expected = IllegalArgumentException.class)
	public void upgradeEncodingWhenEncodedPassIsBogusThenThrowException() {
		encoder.upgradeEncoding("thisIsNoValidHash");
	}


	private void injectPredictableSaltGen() throws Exception {
		byte[] bytes = new byte[16];
		Arrays.fill(bytes, (byte) 0x41);
		Mockito.when(keyGeneratorMock.generateKey()).thenReturn(bytes);

		//we can't use the @InjectMock-annotation because the salt-generator is set in the constructor
		//and Mockito will only inject mocks if they are null
		Field saltGen = encoder.getClass().getDeclaredField("saltGenerator");
		saltGen.setAccessible(true);
		saltGen.set(encoder, keyGeneratorMock);
		saltGen.setAccessible(false);
	}
}
