/*
 * Copyright 2011-2025 the original author or authors.
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

import java.security.SecureRandom;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Random;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.encrypt.AesBytesEncryptor.CipherAlgorithm;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;

import static org.assertj.core.api.Assertions.assertThat;

public class BouncyCastleAesBytesEncryptorEquivalencyTests {

	private byte[] testData;

	private String password;

	private String salt;

	private SecureRandom secureRandom = new SecureRandom();

	@BeforeEach
	public void setup() {
		// generate random password, salt, and test data
		this.password = UUID.randomUUID().toString();
		/** insecure salt byte, recommend 64 or larger than 64 */
		byte[] saltBytes = new byte[16];
		this.secureRandom.nextBytes(saltBytes);
		this.salt = new String(Hex.encode(saltBytes));
	}

	@Test
	public void bouncyCastleAesCbcWithPredictableIvEquivalent() throws Exception {
		CryptoAssumptions.assumeCBCJCE();
		BytesEncryptor bcEncryptor = new BouncyCastleAesCbcBytesEncryptor(this.password, this.salt,
				new PredictableRandomBytesKeyGenerator(16));
		BytesEncryptor jceEncryptor = new AesBytesEncryptor(this.password, this.salt,
				new PredictableRandomBytesKeyGenerator(16));
		testEquivalence(bcEncryptor, jceEncryptor);
	}

	@Test
	public void bouncyCastleAesCbcWithSecureIvCompatible() throws Exception {
		CryptoAssumptions.assumeCBCJCE();
		BytesEncryptor bcEncryptor = new BouncyCastleAesCbcBytesEncryptor(this.password, this.salt,
				KeyGenerators.secureRandom(16));
		BytesEncryptor jceEncryptor = new AesBytesEncryptor(this.password, this.salt, KeyGenerators.secureRandom(16));
		testCompatibility(bcEncryptor, jceEncryptor);
	}

	@Test
	public void bouncyCastleAesGcmWithPredictableIvEquivalent() throws Exception {
		CryptoAssumptions.assumeGCMJCE();
		BytesEncryptor bcEncryptor = new BouncyCastleAesGcmBytesEncryptor(this.password, this.salt,
				new PredictableRandomBytesKeyGenerator(16));
		BytesEncryptor jceEncryptor = new AesBytesEncryptor(this.password, this.salt,
				new PredictableRandomBytesKeyGenerator(16), CipherAlgorithm.GCM);
		testEquivalence(bcEncryptor, jceEncryptor);
	}

	@Test
	public void bouncyCastleAesGcmWithSecureIvCompatible() throws Exception {
		CryptoAssumptions.assumeGCMJCE();
		BytesEncryptor bcEncryptor = new BouncyCastleAesGcmBytesEncryptor(this.password, this.salt,
				KeyGenerators.secureRandom(16));
		BytesEncryptor jceEncryptor = new AesBytesEncryptor(this.password, this.salt, KeyGenerators.secureRandom(16),
				CipherAlgorithm.GCM);
		testCompatibility(bcEncryptor, jceEncryptor);
	}

	@Test
	public void bouncyCastleAesGcmWithAESFastEngineCompatible() throws Exception {
		CryptoAssumptions.assumeGCMJCE();
		BytesEncryptor fastEngineEncryptor = BouncyCastleAesGcmBytesEncryptor.withAESFastEngine(this.password,
				this.salt, KeyGenerators.secureRandom(16));
		BytesEncryptor defaultEngineEncryptor = new BouncyCastleAesGcmBytesEncryptor(this.password, this.salt,
				KeyGenerators.secureRandom(16));
		testCompatibility(fastEngineEncryptor, defaultEngineEncryptor);
	}

	@Test
	public void bouncyCastleAesCbcWithAESFastEngineCompatible() throws Exception {
		CryptoAssumptions.assumeCBCJCE();
		BytesEncryptor fastEngineEncryptor = BouncyCastleAesCbcBytesEncryptor.withAESFastEngine(this.password,
				this.salt, KeyGenerators.secureRandom(16));
		BytesEncryptor defaultEngineEncryptor = new BouncyCastleAesCbcBytesEncryptor(this.password, this.salt,
				KeyGenerators.secureRandom(16));
		testCompatibility(fastEngineEncryptor, defaultEngineEncryptor);
	}

	/**
	 * Comment out @Disabled below to compare relative speed of deprecated AESFastEngine
	 * with the default AESEngine.
	 */
	@Disabled
	@RepeatedTest(100)
	public void bouncyCastleAesGcmWithAESFastEngineSpeedTest() throws Exception {
		CryptoAssumptions.assumeGCMJCE();
		BytesEncryptor defaultEngineEncryptor = new BouncyCastleAesGcmBytesEncryptor(this.password, this.salt,
				KeyGenerators.secureRandom(16));
		BytesEncryptor fastEngineEncryptor = BouncyCastleAesGcmBytesEncryptor.withAESFastEngine(this.password,
				this.salt, KeyGenerators.secureRandom(16));
		long defaultNanos = testSpeed(defaultEngineEncryptor);
		long fastNanos = testSpeed(fastEngineEncryptor);
		System.out.println(nanosToReadableString("AES GCM w/Default Engine", defaultNanos));
		System.out.println(nanosToReadableString("AES GCM w/   Fast Engine", fastNanos));
		assertThat(fastNanos).isLessThan(defaultNanos);
	}

	/**
	 * Comment out @Disabled below to compare relative speed of deprecated AESFastEngine
	 * with the default AESEngine.
	 */
	@Disabled
	@RepeatedTest(100)
	public void bouncyCastleAesCbcWithAESFastEngineSpeedTest() throws Exception {
		CryptoAssumptions.assumeCBCJCE();
		BytesEncryptor defaultEngineEncryptor = new BouncyCastleAesCbcBytesEncryptor(this.password, this.salt,
				KeyGenerators.secureRandom(16));
		BytesEncryptor fastEngineEncryptor = BouncyCastleAesCbcBytesEncryptor.withAESFastEngine(this.password,
				this.salt, KeyGenerators.secureRandom(16));
		long defaultNanos = testSpeed(defaultEngineEncryptor);
		long fastNanos = testSpeed(fastEngineEncryptor);
		System.out.println(nanosToReadableString("AES CBC w/Default Engine", defaultNanos));
		System.out.println(nanosToReadableString("AES CBC w/   Fast Engine", fastNanos));
		assertThat(fastNanos).isLessThan(defaultNanos);
	}

	private void testEquivalence(BytesEncryptor left, BytesEncryptor right) {
		for (int size = 1; size < 2048; size++) {
			this.testData = new byte[size];
			this.secureRandom.nextBytes(this.testData);
			// tests that right and left generate the same encrypted bytes
			// and can decrypt back to the original input
			byte[] leftEncrypted = left.encrypt(this.testData);
			byte[] rightEncrypted = right.encrypt(this.testData);
			assertThat(rightEncrypted).containsExactly(leftEncrypted);
			byte[] leftDecrypted = left.decrypt(leftEncrypted);
			byte[] rightDecrypted = right.decrypt(rightEncrypted);
			assertThat(leftDecrypted).containsExactly(this.testData);
			assertThat(rightDecrypted).containsExactly(this.testData);
		}
	}

	private void testCompatibility(BytesEncryptor left, BytesEncryptor right) {
		// tests that right can decrypt what left encrypted and vice versa
		// and that the decrypted data is the same as the original
		for (int size = 1; size < 2048; size++) {
			this.testData = new byte[size];
			this.secureRandom.nextBytes(this.testData);
			byte[] leftEncrypted = left.encrypt(this.testData);
			byte[] rightEncrypted = right.encrypt(this.testData);
			byte[] leftDecrypted = left.decrypt(rightEncrypted);
			byte[] rightDecrypted = right.decrypt(leftEncrypted);
			assertThat(leftDecrypted).containsExactly(this.testData);
			assertThat(rightDecrypted).containsExactly(this.testData);
		}
	}

	private long testSpeed(BytesEncryptor bytesEncryptor) {
		long start = System.nanoTime();
		for (int size = 0; size < 2048; size++) {
			this.testData = new byte[size];
			this.secureRandom.nextBytes(this.testData);
			byte[] encrypted = bytesEncryptor.encrypt(this.testData);
			byte[] decrypted = bytesEncryptor.decrypt(encrypted);
			assertThat(decrypted).containsExactly(this.testData);
		}
		return System.nanoTime() - start;
	}

	private String nanosToReadableString(String label, long nanos) {
		Duration duration = Duration.ofNanos(nanos);
		Duration millis = duration.truncatedTo(ChronoUnit.MILLIS);
		Duration micros = duration.minus(millis).dividedBy(1000);
		return "%s: %dms %dμs".formatted(label, duration.toMillis(), micros.toNanos());
	}

	/**
	 * A BytesKeyGenerator that always generates the same sequence of values
	 */
	private static class PredictableRandomBytesKeyGenerator implements BytesKeyGenerator {

		private final Random random;

		private final int keyLength;

		PredictableRandomBytesKeyGenerator(int keyLength) {
			this.random = new Random(1);
			this.keyLength = keyLength;
		}

		@Override
		public int getKeyLength() {
			return this.keyLength;
		}

		@Override
		public byte[] generateKey() {
			byte[] bytes = new byte[this.keyLength];
			this.random.nextBytes(bytes);
			return bytes;
		}

	}

}
