/*
 * Copyright 2011-2016 the original author or authors.
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
import java.util.Random;
import java.util.UUID;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.encrypt.AesBytesEncryptor.CipherAlgorithm;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;

public class BouncyCastleAesBytesEncryptorEquivalencyTests {

	private byte[] testData;

	private String password;

	private String salt;

	private SecureRandom secureRandom = new SecureRandom();

	@Before
	public void setup() {
		// generate random password, salt, and test data
		this.password = UUID.randomUUID().toString();
		/** insecure salt byte, recommend 64 or larger than 64 */
		byte[] saltBytes = new byte[16];
		this.secureRandom.nextBytes(saltBytes);
		this.salt = new String(Hex.encode(saltBytes));
	}

	@Test
	public void bouncyCastleAesCbcWithPredictableIvEquvalent() throws Exception {
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
	public void bouncyCastleAesGcmWithPredictableIvEquvalent() throws Exception {
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

	private void testEquivalence(BytesEncryptor left, BytesEncryptor right) {
		for (int size = 1; size < 2048; size++) {
			this.testData = new byte[size];
			this.secureRandom.nextBytes(this.testData);
			// tests that right and left generate the same encrypted bytes
			// and can decrypt back to the original input
			byte[] leftEncrypted = left.encrypt(this.testData);
			byte[] rightEncrypted = right.encrypt(this.testData);
			Assert.assertArrayEquals(leftEncrypted, rightEncrypted);
			byte[] leftDecrypted = left.decrypt(leftEncrypted);
			byte[] rightDecrypted = right.decrypt(rightEncrypted);
			Assert.assertArrayEquals(this.testData, leftDecrypted);
			Assert.assertArrayEquals(this.testData, rightDecrypted);
		}

	}

	private void testCompatibility(BytesEncryptor left, BytesEncryptor right) {
		// tests that right can decrypt what left encrypted and vice versa
		// and that the decypted data is the same as the original
		for (int size = 1; size < 2048; size++) {
			this.testData = new byte[size];
			this.secureRandom.nextBytes(this.testData);
			byte[] leftEncrypted = left.encrypt(this.testData);
			byte[] rightEncrypted = right.encrypt(this.testData);
			byte[] leftDecrypted = left.decrypt(rightEncrypted);
			byte[] rightDecrypted = right.decrypt(leftEncrypted);
			Assert.assertArrayEquals(this.testData, leftDecrypted);
			Assert.assertArrayEquals(this.testData, rightDecrypted);
		}
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
