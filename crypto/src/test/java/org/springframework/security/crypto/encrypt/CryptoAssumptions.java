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

import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.junit.jupiter.api.Assumptions;
import org.opentest4j.TestAbortedException;

import org.springframework.security.crypto.encrypt.AesBytesEncryptor.CipherAlgorithm;

public final class CryptoAssumptions {

	private CryptoAssumptions() {
	}

	public static void assumeGCMJCE() {
		assumeAes256(CipherAlgorithm.GCM);
	}

	public static void assumeCBCJCE() {
		assumeAes256(CipherAlgorithm.CBC);
	}

	private static void assumeAes256(CipherAlgorithm cipherAlgorithm) {
		boolean aes256Available = false;
		try {
			Cipher.getInstance(cipherAlgorithm.toString());
			aes256Available = Cipher.getMaxAllowedKeyLength("AES") >= 256;
		}
		catch (NoSuchAlgorithmException ex) {
			throw new TestAbortedException(cipherAlgorithm + " not available, skipping test", ex);
		}
		catch (NoSuchPaddingException ex) {
			throw new TestAbortedException(cipherAlgorithm + " padding not available, skipping test", ex);
		}
		Assumptions.assumeTrue(aes256Available, "AES key length of 256 not allowed, skipping test");
	}

}
