/*
 * Copyright 2011-2016 the original author or authors.
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
package org.springframework.security.crypto.encrypt;

import java.security.SecureRandom;
import java.util.Random;
import java.util.UUID;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.encrypt.AesBytesEncryptor.CipherAlgorithm;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;

public class BouncyCastleAesBytesEncryptorEquivalencyTest {

	private byte[] testData;
	private String password;
	private String salt;

	@Before
	public void setup() {
		Assume.assumeTrue(
				"couldn't create AesBytesEncryptor, is JCE unlimited strength enabled?",
				isAes256Available());

		// generate random password, salt, and test data
		SecureRandom secureRandom = new SecureRandom();
		password = UUID.randomUUID().toString();
		byte[] saltBytes = new byte[16];
		secureRandom.nextBytes(saltBytes);
		salt = new String(Hex.encode(saltBytes));
		testData = new byte[1024 * 1024];
		secureRandom.nextBytes(testData);
	}

	@Test
	public void bouncyCastleAesCbcWithPredictableIvEquvalent() throws Exception {
		BytesEncryptor bcEncryptor = new BouncyCastleAesCbcBytesEncryptor(password, salt,
				new PredictableRandomBytesKeyGenerator(16));
		BytesEncryptor jceEncryptor = new AesBytesEncryptor(password, salt,
				new PredictableRandomBytesKeyGenerator(16));
		testEquivalence(bcEncryptor, jceEncryptor);
	}

	@Test
	public void bouncyCastleAesCbcWithSecureIvCompatible() throws Exception {
		BytesEncryptor bcEncryptor = new BouncyCastleAesCbcBytesEncryptor(password, salt,
				KeyGenerators.secureRandom(16));
		BytesEncryptor jceEncryptor = new AesBytesEncryptor(password, salt,
				KeyGenerators.secureRandom(16));
		testCompatibility(bcEncryptor, jceEncryptor);
	}

	@Test
	public void bouncyCastleAesGcmWithPredictableIvEquvalent() throws Exception {
		BytesEncryptor bcEncryptor = new BouncyCastleAesGcmBytesEncryptor(password, salt,
				new PredictableRandomBytesKeyGenerator(16));
		BytesEncryptor jceEncryptor = new AesBytesEncryptor(password, salt,
				new PredictableRandomBytesKeyGenerator(16), CipherAlgorithm.GCM);
		testEquivalence(bcEncryptor, jceEncryptor);
	}

	@Test
	public void bouncyCastleAesGcmWithSecureIvCompatible() throws Exception {
		BytesEncryptor bcEncryptor = new BouncyCastleAesGcmBytesEncryptor(password, salt,
				KeyGenerators.secureRandom(16));
		BytesEncryptor jceEncryptor = new AesBytesEncryptor(password, salt,
				KeyGenerators.secureRandom(16), CipherAlgorithm.GCM);
		testCompatibility(bcEncryptor, jceEncryptor);
	}

	private void testEquivalence(BytesEncryptor left, BytesEncryptor right)
			throws Exception {
		// tests that right and left generate the same encrypted bytes
		// and can decrypt back to the original input
		byte[] leftEncrypted = left.encrypt(testData);
		byte[] rightEncrypted = right.encrypt(testData);
		Assert.assertArrayEquals(leftEncrypted, rightEncrypted);
		byte[] leftDecrypted = left.decrypt(leftEncrypted);
		byte[] rightDecrypted = right.decrypt(rightEncrypted);
		Assert.assertArrayEquals(testData, leftDecrypted);
		Assert.assertArrayEquals(testData, rightDecrypted);
	}

	private void testCompatibility(BytesEncryptor left, BytesEncryptor right)
			throws Exception {
		// tests that right can decrypt what left encrypted and vice versa
		// and that the decypted data is the same as the original
		byte[] leftEncrypted = left.encrypt(testData);
		byte[] rightEncrypted = right.encrypt(testData);
		byte[] leftDecrypted = left.decrypt(rightEncrypted);
		byte[] rightDecrypted = right.decrypt(leftEncrypted);
		Assert.assertArrayEquals(testData, leftDecrypted);
		Assert.assertArrayEquals(testData, rightDecrypted);
	}

	private boolean isAes256Available() {
		try {
			return javax.crypto.Cipher.getMaxAllowedKeyLength("AES") >= 256;
		}
		catch (Exception e) {
			return false;
		}

	}

	/**
	 * A BytesKeyGenerator that always generates the same sequence of values
	 */
	private static class PredictableRandomBytesKeyGenerator implements BytesKeyGenerator {

		private final Random random;

		private final int keyLength;

		public PredictableRandomBytesKeyGenerator(int keyLength) {
			this.random = new Random(1);
			this.keyLength = keyLength;
		}

		public int getKeyLength() {
			return keyLength;
		}

		public byte[] generateKey() {
			byte[] bytes = new byte[keyLength];
			random.nextBytes(bytes);
			return bytes;
		}

	}

}
