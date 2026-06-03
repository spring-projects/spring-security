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

package org.springframework.security.crypto.encrypt;

import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;

import org.junit.jupiter.api.Test;

import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link AesGcmBytesEncryptor}.
 */
class AesGcmBytesEncryptorTests {

	private final String secret = "value";

	private final String password = "password";

	private final String hexSalt = "deadbeef";

	@Test
	void roundtripWhenUsingPasswordAndSaltThenEncryptsAndDecrypts() {
		CryptoAssumptions.assumeGCMJCE();
		AesGcmBytesEncryptor encryptor = AesGcmBytesEncryptor.withPassword(this.password, this.hexSalt).build();
		byte[] encrypted = encryptor.encrypt(this.secret.getBytes());
		assertThat(new String(encryptor.decrypt(encrypted))).isEqualTo(this.secret);
	}

	@Test
	void roundtripWhenUsingSecretKeyThenEncryptsAndDecrypts() {
		CryptoAssumptions.assumeGCMJCE();
		PBEKeySpec keySpec = new PBEKeySpec(this.password.toCharArray(), Hex.decode(this.hexSalt), 1024, 256);
		SecretKey secretKey = CipherUtils.newSecretKey(SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA1.name(), keySpec);
		AesGcmBytesEncryptor encryptor = AesGcmBytesEncryptor.withSecretKey(secretKey).build();
		byte[] encrypted = encryptor.encrypt(this.secret.getBytes());
		assertThat(new String(encryptor.decrypt(encrypted))).isEqualTo(this.secret);
	}

	@Test
	void encryptWhenUsingMockIvThenProducesKnownCiphertext() {
		CryptoAssumptions.assumeGCMJCE();
		BytesKeyGenerator mockGenerator = mock(BytesKeyGenerator.class);
		given(mockGenerator.generateKey()).willReturn(Hex.decode("4b0febebd439db7ca77153cb254520c3"));
		given(mockGenerator.getKeyLength()).willReturn(16);
		AesGcmBytesEncryptor encryptor = AesGcmBytesEncryptor.withPassword(this.password, this.hexSalt)
			.ivGenerator(mockGenerator)
			.build();
		byte[] encrypted = encryptor.encrypt(this.secret.getBytes());
		assertThat(Hex.encode(encrypted))
			.isEqualTo("4b0febebd439db7ca77153cb254520c3e4d61ae38207b4e42b820d311dc3d4e0e2f37ed5ee");
		assertThat(new String(encryptor.decrypt(encrypted))).isEqualTo(this.secret);
	}

	@Test
	void encryptProducesUniqueOutputAndIvIsPrepended() {
		CryptoAssumptions.assumeGCMJCE();
		AesGcmBytesEncryptor encryptor = AesGcmBytesEncryptor.withPassword(this.password, this.hexSalt).build();
		byte[] first = encryptor.encrypt(this.secret.getBytes());
		byte[] second = encryptor.encrypt(this.secret.getBytes());
		assertThat(first).isNotEqualTo(second);
		assertThat(first.length).isGreaterThan(32);
	}

	@Test
	@SuppressWarnings("deprecation")
	void withSecretWhenAesBytesEncryptorEncryptsThenDecrypts() {
		CryptoAssumptions.assumeGCMJCE();
		PBEKeySpec keySpec = new PBEKeySpec(this.password.toCharArray(), Hex.decode(this.hexSalt), 1024, 256);
		SecretKey key = CipherUtils.newSecretKey(SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA1.name(), keySpec);
		AesBytesEncryptor deprecated = new AesBytesEncryptor(key, KeyGenerators.secureRandom(16),
				AesBytesEncryptor.CipherAlgorithm.GCM);
		AesGcmBytesEncryptor encryptor = AesGcmBytesEncryptor.withSecretKey(key).build();
		byte[] encrypted = deprecated.encrypt(this.secret.getBytes());
		assertThat(new String(encryptor.decrypt(encrypted))).isEqualTo(this.secret);
	}

	@Test
	@SuppressWarnings("deprecation")
	void aesBytesEncryptorWhenEncryptsThenAesGcmBytesEncryptorDecrypts() {
		CryptoAssumptions.assumeGCMJCE();
		PBEKeySpec keySpec = new PBEKeySpec(this.password.toCharArray(), Hex.decode(this.hexSalt), 1024, 256);
		SecretKey key = CipherUtils.newSecretKey(SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA1.name(), keySpec);
		AesGcmBytesEncryptor encryptor = AesGcmBytesEncryptor.withSecretKey(key)
			.ivGenerator(KeyGenerators.secureRandom(12))
			.build();
		AesBytesEncryptor deprecated = new AesBytesEncryptor(key, KeyGenerators.secureRandom(12),
				AesBytesEncryptor.CipherAlgorithm.GCM);
		byte[] encrypted = encryptor.encrypt(this.secret.getBytes());
		assertThat(new String(deprecated.decrypt(encrypted))).isEqualTo(this.secret);
	}

	@Test
	void roundtripWhenUsingCustomIvGeneratorLengthThenEncryptsAndDecrypts() {
		CryptoAssumptions.assumeGCMJCE();
		AesGcmBytesEncryptor encryptor = AesGcmBytesEncryptor.withPassword(this.password, this.hexSalt)
			.ivGenerator(KeyGenerators.secureRandom(12))
			.build();
		byte[] encrypted = encryptor.encrypt(this.secret.getBytes());
		assertThat(new String(encryptor.decrypt(encrypted))).isEqualTo(this.secret);
	}

	@Test
	@SuppressWarnings("deprecation")
	void withPasswordDerivesADifferentKeyThanAesBytesEncryptor() {
		CryptoAssumptions.assumeGCMJCE();
		AesBytesEncryptor deprecated = new AesBytesEncryptor(this.password, this.hexSalt,
				KeyGenerators.secureRandom(16), AesBytesEncryptor.CipherAlgorithm.GCM);
		AesGcmBytesEncryptor encryptor = AesGcmBytesEncryptor.withPassword(this.password, this.hexSalt).build();
		byte[] encrypted = deprecated.encrypt(this.secret.getBytes());
		assertThatIllegalStateException().isThrownBy(() -> encryptor.decrypt(encrypted));
	}

	@Test
	void decryptDetectsAuthenticationTagTampering() {
		CryptoAssumptions.assumeGCMJCE();
		AesGcmBytesEncryptor encryptor = AesGcmBytesEncryptor.withPassword(this.password, this.hexSalt).build();
		byte[] encrypted = encryptor.encrypt(this.secret.getBytes());
		encrypted[17] ^= 0xFF;
		assertThatIllegalStateException().isThrownBy(() -> encryptor.decrypt(encrypted));
	}

}
