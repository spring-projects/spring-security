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

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CBCModeCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;

import org.springframework.security.crypto.encrypt.AesBytesEncryptor.CipherAlgorithm;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.util.EncodingUtils;

/**
 * An Encryptor equivalent to {@link AesBytesEncryptor} using {@link CipherAlgorithm#CBC}
 * that uses Bouncy Castle instead of JCE. The algorithm is equivalent to
 * "AES/CBC/PKCS5Padding".
 *
 * @author William Tran
 */
public class BouncyCastleAesCbcBytesEncryptor extends BouncyCastleAesBytesEncryptor {

	private Supplier<CBCModeCipher> cipherFactory = () -> CBCBlockCipher.newInstance(AESEngine.newInstance());

	public BouncyCastleAesCbcBytesEncryptor(String password, CharSequence salt) {
		super(password, salt);
	}

	public BouncyCastleAesCbcBytesEncryptor(String password, CharSequence salt, BytesKeyGenerator ivGenerator) {
		super(password, salt, ivGenerator);
	}

	@Override
	public byte[] encrypt(byte[] bytes) {
		byte[] iv = this.ivGenerator.generateKey();
		PaddedBufferedBlockCipher blockCipher = new PaddedBufferedBlockCipher(this.cipherFactory.get(),
				new PKCS7Padding());
		blockCipher.init(true, new ParametersWithIV(this.secretKey, iv));
		byte[] encrypted = process(blockCipher, bytes);
		return (iv != null) ? EncodingUtils.concatenate(iv, encrypted) : encrypted;
	}

	@Override
	public byte[] decrypt(byte[] encryptedBytes) {
		byte[] iv = EncodingUtils.subArray(encryptedBytes, 0, this.ivGenerator.getKeyLength());
		encryptedBytes = EncodingUtils.subArray(encryptedBytes, this.ivGenerator.getKeyLength(), encryptedBytes.length);
		PaddedBufferedBlockCipher blockCipher = new PaddedBufferedBlockCipher(this.cipherFactory.get(),
				new PKCS7Padding());
		blockCipher.init(false, new ParametersWithIV(this.secretKey, iv));
		return process(blockCipher, encryptedBytes);
	}

	private byte[] process(BufferedBlockCipher blockCipher, byte[] in) {
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
	static BouncyCastleAesCbcBytesEncryptor withAESFastEngine(String password, CharSequence salt,
			BytesKeyGenerator ivGenerator) {
		BouncyCastleAesCbcBytesEncryptor bytesEncryptor = new BouncyCastleAesCbcBytesEncryptor(password, salt,
				ivGenerator);
		bytesEncryptor.cipherFactory = () -> new CBCBlockCipher(new AESFastEngine());

		return bytesEncryptor;
	}

}
