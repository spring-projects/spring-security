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

package org.springframework.security.crypto.argon2;

import java.lang.reflect.Field;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.password.AbstractPasswordEncoderValidationTests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * @author Simeon Macke
 */
@ExtendWith(MockitoExtension.class)
public class Argon2PasswordEncoderTests extends AbstractPasswordEncoderValidationTests {

	@Mock
	private BytesKeyGenerator keyGeneratorMock;

	@BeforeEach
	void setup() {
		setEncoder(Argon2PasswordEncoder.defaultsForSpringSecurity_v5_2());
	}

	@Test
	public void encodedNonNullPasswordDoesNotEqualPassword() {
		String result = getEncoder().encode("password");
		assertThat(result).isNotEqualTo("password");
	}

	@Test
	public void encodedNonNullPasswordWhenEqualPasswordThenMatches() {
		String result = getEncoder().encode("password");
		assertThat(getEncoder().matches("password", result)).isTrue();
	}

	@Test
	public void encodedNonNullPasswordWhenEqualWithUnicodeThenMatches() {
		String result = getEncoder().encode("passw\u9292rd");
		assertThat(getEncoder().matches("pass\u9292\u9292rd", result)).isFalse();
		assertThat(getEncoder().matches("passw\u9292rd", result)).isTrue();
	}

	@Test
	public void encodedNonNullPasswordWhenNotEqualThenNotMatches() {
		String result = getEncoder().encode("password");
		assertThat(getEncoder().matches("bogus", result)).isFalse();
	}

	@Test
	public void encodedNonNullPasswordWhenEqualPasswordWithCustomParamsThenMatches() {
		setEncoder(new Argon2PasswordEncoder(20, 64, 4, 256, 4));
		String result = getEncoder().encode("password");
		assertThat(getEncoder().matches("password", result)).isTrue();
	}

	@Test
	public void encodedNonNullPasswordWhenRanTwiceThenResultsNotEqual() {
		String password = "secret";
		assertThat(getEncoder().encode(password)).isNotEqualTo(getEncoder().encode(password));
	}

	@Test
	public void encodedNonNullPasswordWhenRanTwiceWithCustomParamsThenNotEquals() {
		setEncoder(new Argon2PasswordEncoder(20, 64, 4, 256, 4));
		String password = "secret";
		assertThat(getEncoder().encode(password)).isNotEqualTo(getEncoder().encode(password));
	}

	@Test
	public void matchesWhenGeneratedWithDifferentEncoderThenTrue() {
		Argon2PasswordEncoder oldEncoder = new Argon2PasswordEncoder(20, 64, 4, 256, 4);
		Argon2PasswordEncoder newEncoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_2();
		String password = "secret";
		String oldEncodedPassword = oldEncoder.encode(password);
		assertThat(newEncoder.matches(password, oldEncodedPassword)).isTrue();
	}

	@Test
	public void matchesWhenEncodedPassIsNullThenFalse() {
		assertThat(getEncoder().matches("password", null)).isFalse();
	}

	@Test
	public void matchesWhenEncodedPassIsEmptyThenFalse() {
		assertThat(getEncoder().matches("password", "")).isFalse();
	}

	@Test
	public void matchesWhenEncodedPassIsBogusThenFalse() {
		assertThat(getEncoder().matches("password", "012345678901234567890123456789")).isFalse();
	}

	@Test
	public void encodedNonNullPasswordWhenUsingPredictableSaltThenEqualTestHash() throws Exception {
		injectPredictableSaltGen();
		String hash = getEncoder().encode("sometestpassword");
		assertThat(hash).isEqualTo(
				"$argon2id$v=19$m=4096,t=3,p=1$QUFBQUFBQUFBQUFBQUFBQQ$hmmTNyJlwbb6HAvFoHFWF+u03fdb0F2qA+39oPlcAqo");
	}

	@Test
	public void encodedNonNullPasswordWhenUsingPredictableSaltWithCustomParamsThenEqualTestHash() throws Exception {
		setEncoder(new Argon2PasswordEncoder(16, 32, 4, 512, 5));
		injectPredictableSaltGen();
		String hash = getEncoder().encode("sometestpassword");
		assertThat(hash).isEqualTo(
				"$argon2id$v=19$m=512,t=5,p=4$QUFBQUFBQUFBQUFBQUFBQQ$PNv4C3K50bz3rmON+LtFpdisD7ePieLNq+l5iUHgc1k");
	}

	@Test
	public void encodedNonNullPasswordWhenUsingPredictableSaltWithDefaultsForSpringSecurity_v5_8ThenEqualTestHash()
			throws Exception {
		setEncoder(Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8());
		injectPredictableSaltGen();
		String hash = getEncoder().encode("sometestpassword");
		assertThat(hash).isEqualTo(
				"$argon2id$v=19$m=16384,t=2,p=1$QUFBQUFBQUFBQUFBQUFBQQ$zGt5MiNPSUOo4/7jBcJMayCPfcsLJ4c0WUxhwGDIYPw");
	}

	@Test
	public void upgradeEncodingWhenSameEncodingThenFalse() {
		String hash = getEncoder().encode("password");
		assertThat(getEncoder().upgradeEncoding(hash)).isFalse();
	}

	@Test
	public void upgradeEncodingWhenSameStandardParamsThenFalse() {
		Argon2PasswordEncoder newEncoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_2();
		String hash = getEncoder().encode("password");
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
		assertThat(getEncoder().upgradeEncoding(null)).isFalse();
	}

	@Test
	public void upgradeEncodingWhenEncodedPassIsEmptyThenFalse() {
		assertThat(getEncoder().upgradeEncoding("")).isFalse();
	}

	@Test
	public void upgradeEncodingWhenEncodedPassIsBogusThenThrowException() {
		assertThatIllegalArgumentException().isThrownBy(() -> getEncoder().upgradeEncoding("thisIsNoValidHash"));
	}

	private void injectPredictableSaltGen() throws Exception {
		byte[] bytes = new byte[16];
		Arrays.fill(bytes, (byte) 0x41);
		Mockito.when(this.keyGeneratorMock.generateKey()).thenReturn(bytes);
		// we can't use the @InjectMock-annotation because the salt-generator is set in
		// the constructor
		// and Mockito will only inject mocks if they are null
		Field saltGen = getEncoder().getClass().getDeclaredField("saltGenerator");
		saltGen.setAccessible(true);
		saltGen.set(getEncoder(), this.keyGeneratorMock);
		saltGen.setAccessible(false);
	}

}
