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

import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.util.EncodingUtils;

/**
 * {@link BytesEncryptor} that uses 256-bit AES/GCM/NoPadding with a random 16-byte
 * initialization vector and a 128-bit authentication tag. The IV is prepended to the
 * ciphertext on encrypt and stripped on decrypt. GCM provides authenticated encryption
 * (AEAD): both confidentiality and integrity are protected, and decryption throws if the
 * ciphertext has been tampered with.
 *
 * <p>
 * This class uses a 16-byte (128-bit) IV rather than the 12-byte (96-bit) IV recommended
 * by NIST SP 800-38D for GCM. Both lengths are cryptographically valid; the 16-byte
 * choice maintains consistency with the rest of the Spring Security crypto module. For
 * additional guidance, please see the <a href=
 * "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html">
 * OWASP Cryptographic Storage Cheat Sheet</a>.
 *
 * <p>
 * When key derivation is used via {@link #withPassword(String, CharSequence)}, the key is
 * derived using PBKDF2WithHmacSHA256 with {@code DEFAULT_PBKDF2_ITERATIONS} iterations
 * per the <a href=
 * "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html">
 * OWASP Password Storage Cheat Sheet</a>. Because derivation is intentionally expensive,
 * the encryptor instance should be created once and reused rather than constructed
 * per-operation.
 *
 * @author Josh Cummings
 * @since 5.7.26
 * @see AesCbcBytesEncryptor
 * @see AesBytesEncryptor
 */
public final class AesGcmBytesEncryptor implements BytesEncryptor {

	private static final String ALGORITHM = "AES/GCM/NoPadding";

	private static final int IV_LENGTH_BYTES = 16;

	private static final int TAG_LENGTH_BITS = 128;

	private static final int DEFAULT_PBKDF2_ITERATIONS = 600_000;

	private final SecretKey secretKey;

	private final Cipher encryptor;

	private final Cipher decryptor;

	private final BytesKeyGenerator ivGenerator;

	private AesGcmBytesEncryptor(SecretKey secretKey, BytesKeyGenerator ivGenerator) {
		this.secretKey = new SecretKeySpec(secretKey.getEncoded(), "AES");
		this.encryptor = CipherUtils.newCipher(ALGORITHM);
		this.decryptor = CipherUtils.newCipher(ALGORITHM);
		this.ivGenerator = ivGenerator;
	}

	/**
	 * Creates an encryptor that derives its key from the given password and hex-encoded
	 * salt using PBKDF2WithHmacSHA1.
	 * @param password the password value
	 * @param salt the hex-encoded salt value
	 */
	public static Builder withPassword(String password, CharSequence salt) {
		return new Builder(password, salt);
	}

	/**
	 * Creates an encryptor using the supplied {@link SecretKey}.
	 * @param secretKey the secret (symmetric) key
	 */
	public static Builder withSecretKey(SecretKey secretKey) {
		return new Builder(secretKey);
	}

	@Override
	public byte[] encrypt(byte[] bytes) {
		synchronized (this.encryptor) {
			byte[] iv = this.ivGenerator.generateKey();
			CipherUtils.initCipher(this.encryptor, Cipher.ENCRYPT_MODE, this.secretKey,
					new GCMParameterSpec(TAG_LENGTH_BITS, iv));
			byte[] ciphertext = CipherUtils.doFinal(this.encryptor, bytes);
			return EncodingUtils.concatenate(iv, ciphertext);
		}
	}

	@Override
	public byte[] decrypt(byte[] encryptedBytes) {
		int ivLength = this.ivGenerator.getKeyLength();
		byte[] iv = EncodingUtils.subArray(encryptedBytes, 0, ivLength);
		byte[] ciphertext = EncodingUtils.subArray(encryptedBytes, ivLength, encryptedBytes.length);
		synchronized (this.decryptor) {
			CipherUtils.initCipher(this.decryptor, Cipher.DECRYPT_MODE, this.secretKey,
					new GCMParameterSpec(TAG_LENGTH_BITS, iv));
			return CipherUtils.doFinal(this.decryptor, ciphertext);
		}
	}

	private static SecretKey deriveKey(String password, CharSequence salt) {
		return CipherUtils.newSecretKey("PBKDF2WithHmacSHA256",
				new PBEKeySpec(password.toCharArray(), Hex.decode(salt), DEFAULT_PBKDF2_ITERATIONS, 256));
	}

	/**
	 * A Builder for {@link AesGcmBytesEncryptor}.
	 */
	public static final class Builder {

		private final SecretKey secretKey;

		private BytesKeyGenerator ivGenerator = KeyGenerators.secureRandom(IV_LENGTH_BYTES);

		private Builder(SecretKey secretKey) {
			this.secretKey = secretKey;
		}

		private Builder(String password, CharSequence salt) {
			this.secretKey = deriveKey(password, salt);
		}

		/**
		 * Sets the {@link BytesKeyGenerator} to use for generating the initialization
		 * vector.
		 * @param ivGenerator the {@link BytesKeyGenerator} to use for generating the
		 * initialization vector
		 * @return this builder
		 */
		public Builder ivGenerator(BytesKeyGenerator ivGenerator) {
			Objects.requireNonNull(ivGenerator, "ivGenerator cannot be null");
			this.ivGenerator = ivGenerator;
			return this;
		}

		/**
		 * Builds the {@link AesGcmBytesEncryptor}.
		 * @return the {@link AesGcmBytesEncryptor}
		 */
		public AesGcmBytesEncryptor build() {
			return new AesGcmBytesEncryptor(this.secretKey, this.ivGenerator);
		}

	}

}
