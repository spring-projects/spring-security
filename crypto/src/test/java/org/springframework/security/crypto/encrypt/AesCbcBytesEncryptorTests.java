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

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;

import org.junit.jupiter.api.Test;

import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm;
import org.springframework.security.crypto.util.EncodingUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link AesCbcBytesEncryptor}.
 */
class AesCbcBytesEncryptorTests {

	private final String secret = "value";

	private final String password = "password";

	private final String hexSalt = "deadbeef";

	@Test
	void roundtripWhenUsingPasswordAndSaltThenEncryptsAndDecrypts() {
		CryptoAssumptions.assumeCBCJCE();
		AesCbcBytesEncryptor encryptor = AesCbcBytesEncryptor.withPassword(this.password, this.hexSalt).build();
		byte[] encrypted = encryptor.encrypt(this.secret.getBytes());
		assertThat(new String(encryptor.decrypt(encrypted))).isEqualTo(this.secret);
	}

	@Test
	void roundtripWhenUsingSecretKeyThenEncryptsAndDecrypts() {
		CryptoAssumptions.assumeCBCJCE();
		PBEKeySpec keySpec = new PBEKeySpec(this.password.toCharArray(), HexFormat.of().parseHex(this.hexSalt), 1024,
				256);
		SecretKey secretKey = CipherUtils.newSecretKey(SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA1.name(), keySpec);
		AesCbcBytesEncryptor encryptor = AesCbcBytesEncryptor.withSecretKey(secretKey).build();
		byte[] encrypted = encryptor.encrypt(this.secret.getBytes());
		assertThat(new String(encryptor.decrypt(encrypted))).isEqualTo(this.secret);
	}

	@Test
	void encryptWhenUsingMockIvThenProducesKnownCiphertext() {
		CryptoAssumptions.assumeCBCJCE();
		BytesKeyGenerator mockGenerator = mock(BytesKeyGenerator.class);
		given(mockGenerator.generateKey()).willReturn(HexFormat.of().parseHex("4b0febebd439db7ca77153cb254520c3"));
		given(mockGenerator.getKeyLength()).willReturn(16);
		AesCbcBytesEncryptor encryptor = AesCbcBytesEncryptor.withPassword(this.password, this.hexSalt)
			.ivGenerator(mockGenerator)
			.build();
		byte[] encrypted = encryptor.encrypt(this.secret.getBytes());
		assertThat(HexFormat.of().formatHex(encrypted))
			.isEqualTo("4b0febebd439db7ca77153cb254520c3b7232ac29355d07869433f1ecf55fe94");
		assertThat(new String(encryptor.decrypt(encrypted))).isEqualTo(this.secret);
	}

	@Test
	void encryptProducesUniqueOutputAndIvIsPrePended() {
		CryptoAssumptions.assumeCBCJCE();
		AesCbcBytesEncryptor encryptor = AesCbcBytesEncryptor.withPassword(this.password, this.hexSalt).build();
		byte[] first = encryptor.encrypt(this.secret.getBytes());
		byte[] second = encryptor.encrypt(this.secret.getBytes());
		assertThat(first).isNotEqualTo(second);
		assertThat(first.length).isGreaterThan(16);
	}

	@Test
	@SuppressWarnings("deprecation")
	void migratesFromDeprecatedNullIvCbcToAesCbcBytesEncryptor() {
		CryptoAssumptions.assumeCBCJCE();
		AesBytesEncryptor deprecated = new AesBytesEncryptor(this.password, this.hexSalt);
		byte[] encrypted = deprecated.encrypt(this.secret.getBytes());

		AesCbcBytesEncryptor modern = AesCbcBytesEncryptor.withPassword(this.password, this.hexSalt).build();
		BytesEncryptor migrating = new MigratingBytesEncryptor("{CBC}", modern, deprecated);

		assertThat(new String(migrating.decrypt(encrypted))).isEqualTo(this.secret);

		byte[] migrated = migrating.encrypt(this.secret.getBytes());
		assertThat(migrated[0]).isEqualTo((byte) '{');
		assertThat(migrated[1]).isEqualTo((byte) 'C');
		assertThat(migrated[2]).isEqualTo((byte) 'B');
		assertThat(migrated[3]).isEqualTo((byte) 'C');
		assertThat(migrated[4]).isEqualTo((byte) '}');
		assertThat(new String(migrating.decrypt(migrated))).isEqualTo(this.secret);
	}

	@Test
	@SuppressWarnings("deprecation")
	void withSecretWhenAesBytesEncryptorEncryptsThenDecrypts() {
		CryptoAssumptions.assumeCBCJCE();
		PBEKeySpec keySpec = new PBEKeySpec(this.password.toCharArray(), HexFormat.of().parseHex(this.hexSalt), 1024,
				256);
		SecretKey key = CipherUtils.newSecretKey(SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA1.name(), keySpec);
		AesBytesEncryptor deprecated = new AesBytesEncryptor(key, KeyGenerators.secureRandom(16),
				AesBytesEncryptor.CipherAlgorithm.CBC);
		AesCbcBytesEncryptor encryptor = AesCbcBytesEncryptor.withSecretKey(key).build();
		byte[] encrypted = deprecated.encrypt(this.secret.getBytes());
		assertThat(new String(encryptor.decrypt(encrypted))).isEqualTo(this.secret);
	}

	@Test
	@SuppressWarnings("deprecation")
	void aesBytesEncryptorWhenEncryptsThenAesCbcBytesEncryptorDecrypts() {
		CryptoAssumptions.assumeCBCJCE();
		PBEKeySpec keySpec = new PBEKeySpec(this.password.toCharArray(), HexFormat.of().parseHex(this.hexSalt), 1024,
				256);
		SecretKey key = CipherUtils.newSecretKey(SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA1.name(), keySpec);
		AesCbcBytesEncryptor encryptor = AesCbcBytesEncryptor.withSecretKey(key).build();
		AesBytesEncryptor deprecated = new AesBytesEncryptor(key, KeyGenerators.secureRandom(16),
				AesBytesEncryptor.CipherAlgorithm.CBC);
		byte[] encrypted = encryptor.encrypt(this.secret.getBytes());
		assertThat(new String(deprecated.decrypt(encrypted))).isEqualTo(this.secret);
	}

	@Test
	void roundtripWhenUsingCustomIvGeneratorThenEncryptsAndDecrypts() {
		CryptoAssumptions.assumeCBCJCE();
		BytesKeyGenerator customIvGenerator = mock(BytesKeyGenerator.class);
		given(customIvGenerator.generateKey()).willReturn(HexFormat.of().parseHex("4b0febebd439db7ca77153cb254520c3"));
		given(customIvGenerator.getKeyLength()).willReturn(16);
		AesCbcBytesEncryptor encryptor = AesCbcBytesEncryptor.withPassword(this.password, this.hexSalt)
			.ivGenerator(customIvGenerator)
			.build();
		byte[] encrypted = encryptor.encrypt(this.secret.getBytes());
		assertThat(new String(encryptor.decrypt(encrypted))).isEqualTo(this.secret);
	}

	@Test
	@SuppressWarnings("deprecation")
	void withPasswordDerivesADifferentKeyThanAesBytesEncryptor() {
		CryptoAssumptions.assumeCBCJCE();
		AesBytesEncryptor deprecated = new AesBytesEncryptor(this.password, this.hexSalt,
				KeyGenerators.secureRandom(16));
		AesCbcBytesEncryptor encryptor = AesCbcBytesEncryptor.withPassword(this.password, this.hexSalt).build();
		byte[] encrypted = deprecated.encrypt(this.secret.getBytes());
		assertThatIllegalStateException().isThrownBy(() -> encryptor.decrypt(encrypted));
	}

	private static final class MigratingBytesEncryptor implements BytesEncryptor {

		private final byte[] prefix;

		private final BytesEncryptor write;

		private final BytesEncryptor deprecated;

		MigratingBytesEncryptor(String prefix, BytesEncryptor write, BytesEncryptor deprecated) {
			this.prefix = prefix.getBytes(StandardCharsets.US_ASCII);
			this.write = write;
			this.deprecated = deprecated;
		}

		@Override
		public byte[] encrypt(byte[] bytes) {
			return EncodingUtils.concatenate(this.prefix, this.write.encrypt(bytes));
		}

		@Override
		public byte[] decrypt(byte[] encryptedBytes) {
			if (startsWith(encryptedBytes, this.prefix)) {
				byte[] bytes = EncodingUtils.subArray(encryptedBytes, this.prefix.length, encryptedBytes.length);
				return this.write.decrypt(bytes);
			}
			return this.deprecated.decrypt(encryptedBytes);
		}

		private static boolean startsWith(byte[] data, byte[] prefix) {
			if (data.length < prefix.length) {
				return false;
			}
			for (int i = 0; i < prefix.length; i++) {
				if (data[i] != prefix[i]) {
					return false;
				}
			}
			return true;
		}

	}

}
