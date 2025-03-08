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

import java.util.function.Supplier;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;

import org.springframework.security.crypto.encrypt.AesBytesEncryptor.CipherAlgorithm;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.util.EncodingUtils;

/**
 * An Encryptor equivalent to {@link AesBytesEncryptor} using {@link CipherAlgorithm#GCM}
 * that uses Bouncy Castle instead of JCE. The algorithm is equivalent to
 * "AES/GCM/NoPadding".
 *
 * @author William Tran
 *
 */
public class BouncyCastleAesGcmBytesEncryptor extends BouncyCastleAesBytesEncryptor {

	private Supplier<GCMBlockCipher> cipherFactory = () -> (GCMBlockCipher) GCMBlockCipher
		.newInstance(AESEngine.newInstance());

	public BouncyCastleAesGcmBytesEncryptor(String password, CharSequence salt) {
		super(password, salt);
	}

	public BouncyCastleAesGcmBytesEncryptor(String password, CharSequence salt, BytesKeyGenerator ivGenerator) {
		super(password, salt, ivGenerator);
	}

	@Override
	public byte[] encrypt(byte[] bytes) {
		byte[] iv = this.ivGenerator.generateKey();
		AEADBlockCipher blockCipher = this.cipherFactory.get();
		blockCipher.init(true, new AEADParameters(this.secretKey, 128, iv, null));
		byte[] encrypted = process(blockCipher, bytes);
		return (iv != null) ? EncodingUtils.concatenate(iv, encrypted) : encrypted;
	}

	@Override
	public byte[] decrypt(byte[] encryptedBytes) {
		byte[] iv = EncodingUtils.subArray(encryptedBytes, 0, this.ivGenerator.getKeyLength());
		encryptedBytes = EncodingUtils.subArray(encryptedBytes, this.ivGenerator.getKeyLength(), encryptedBytes.length);
		AEADBlockCipher blockCipher = this.cipherFactory.get();
		blockCipher.init(false, new AEADParameters(this.secretKey, 128, iv, null));
		return process(blockCipher, encryptedBytes);
	}

	private byte[] process(AEADBlockCipher blockCipher, byte[] in) {
		byte[] buf = new byte[blockCipher.getOutputSize(in.length)];
		int bytesWritten = blockCipher.processBytes(in, 0, in.length, buf, 0);
		try {
			bytesWritten += blockCipher.doFinal(buf, bytesWritten);
		}
		catch (InvalidCipherTextException ex) {
			throw new IllegalStateException("unable to encrypt/decrypt", ex);
		}
		if (bytesWritten == buf.length) {
			return buf;
		}
		byte[] out = new byte[bytesWritten];
		System.arraycopy(buf, 0, out, 0, bytesWritten);
		return out;
	}

	/**
	 * Used to test compatibility with deprecated {@link AESFastEngine}.
	 */
	@SuppressWarnings("deprecation")
	static BouncyCastleAesGcmBytesEncryptor withAESFastEngine(String password, CharSequence salt,
			BytesKeyGenerator ivGenerator) {
		BouncyCastleAesGcmBytesEncryptor bytesEncryptor = new BouncyCastleAesGcmBytesEncryptor(password, salt,
				ivGenerator);
		bytesEncryptor.cipherFactory = () -> new GCMBlockCipher(new AESFastEngine());

		return bytesEncryptor;
	}

}
