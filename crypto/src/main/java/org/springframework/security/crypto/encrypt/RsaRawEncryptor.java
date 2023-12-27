/*
 * Copyright 2013-2024 the original author or authors.
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

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import javax.crypto.Cipher;

/**
 * @author Dave Syer
 * @since 6.3
 */
public class RsaRawEncryptor implements BytesEncryptor, TextEncryptor, RsaKeyHolder {

	private static final String DEFAULT_ENCODING = "UTF-8";

	private RsaAlgorithm algorithm = RsaAlgorithm.DEFAULT;

	private Charset charset;

	private RSAPublicKey publicKey;

	private RSAPrivateKey privateKey;

	private Charset defaultCharset;

	public RsaRawEncryptor(RsaAlgorithm algorithm) {
		this(RsaKeyHelper.generateKeyPair(), algorithm);
	}

	public RsaRawEncryptor() {
		this(RsaKeyHelper.generateKeyPair());
	}

	public RsaRawEncryptor(KeyPair keyPair, RsaAlgorithm algorithm) {
		this(DEFAULT_ENCODING, keyPair.getPublic(), keyPair.getPrivate(), algorithm);
	}

	public RsaRawEncryptor(KeyPair keyPair) {
		this(DEFAULT_ENCODING, keyPair.getPublic(), keyPair.getPrivate());
	}

	public RsaRawEncryptor(String pemData) {
		this(RsaKeyHelper.parseKeyPair(pemData));
	}

	public RsaRawEncryptor(PublicKey publicKey) {
		this(DEFAULT_ENCODING, publicKey, null);
	}

	public RsaRawEncryptor(String encoding, PublicKey publicKey, PrivateKey privateKey) {
		this(encoding, publicKey, privateKey, RsaAlgorithm.DEFAULT);
	}

	public RsaRawEncryptor(String encoding, PublicKey publicKey, PrivateKey privateKey, RsaAlgorithm algorithm) {
		this.charset = Charset.forName(encoding);
		this.publicKey = (RSAPublicKey) publicKey;
		this.privateKey = (RSAPrivateKey) privateKey;
		this.defaultCharset = Charset.forName(DEFAULT_ENCODING);
		this.algorithm = algorithm;
	}

	@Override
	public String getPublicKey() {
		return RsaKeyHelper.encodePublicKey(this.publicKey, "application");
	}

	@Override
	public String encrypt(String text) {
		return new String(Base64.getEncoder().encode(encrypt(text.getBytes(this.charset))), this.defaultCharset);
	}

	@Override
	public String decrypt(String encryptedText) {
		if (this.privateKey == null) {
			throw new IllegalStateException("Private key must be provided for decryption");
		}
		return new String(decrypt(Base64.getDecoder().decode(encryptedText.getBytes(this.defaultCharset))),
				this.charset);
	}

	@Override
	public byte[] encrypt(byte[] byteArray) {
		return encrypt(byteArray, this.publicKey, this.algorithm);
	}

	@Override
	public byte[] decrypt(byte[] encryptedByteArray) {
		return decrypt(encryptedByteArray, this.privateKey, this.algorithm);
	}

	private static byte[] encrypt(byte[] text, PublicKey key, RsaAlgorithm alg) {
		ByteArrayOutputStream output = new ByteArrayOutputStream(text.length);
		try {
			final Cipher cipher = Cipher.getInstance(alg.getJceName());
			int limit = Math.min(text.length, alg.getMaxLength());
			int pos = 0;
			while (pos < text.length) {
				cipher.init(Cipher.ENCRYPT_MODE, key);
				cipher.update(text, pos, limit);
				pos += limit;
				limit = Math.min(text.length - pos, alg.getMaxLength());
				byte[] buffer = cipher.doFinal();
				output.write(buffer, 0, buffer.length);
			}
			return output.toByteArray();
		}
		catch (RuntimeException ex) {
			throw ex;
		}
		catch (Exception ex) {
			throw new IllegalStateException("Cannot encrypt", ex);
		}
	}

	private static byte[] decrypt(byte[] text, RSAPrivateKey key, RsaAlgorithm alg) {
		ByteArrayOutputStream output = new ByteArrayOutputStream(text.length);
		try {
			final Cipher cipher = Cipher.getInstance(alg.getJceName());
			int maxLength = getByteLength(key);
			int pos = 0;
			while (pos < text.length) {
				int limit = Math.min(text.length - pos, maxLength);
				cipher.init(Cipher.DECRYPT_MODE, key);
				cipher.update(text, pos, limit);
				pos += limit;
				byte[] buffer = cipher.doFinal();
				output.write(buffer, 0, buffer.length);
			}
			return output.toByteArray();
		}
		catch (RuntimeException ex) {
			throw ex;
		}
		catch (Exception ex) {
			throw new IllegalStateException("Cannot decrypt", ex);
		}
	}

	// copied from sun.security.rsa.RSACore.getByteLength(java.math.BigInteger)
	public static int getByteLength(RSAKey key) {
		int n = key.getModulus().bitLength();
		return (n + 7) >> 3;
	}

}
