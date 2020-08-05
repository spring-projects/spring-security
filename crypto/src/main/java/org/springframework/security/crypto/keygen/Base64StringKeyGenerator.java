/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.crypto.keygen;

import java.util.Base64;

/**
 * A StringKeyGenerator that generates base64-encoded String keys. Delegates to a
 * {@link BytesKeyGenerator} for the actual key generation.
 *
 * @author Joe Grandja
 * @author Rob Winch
 * @since 5.0
 */
public class Base64StringKeyGenerator implements StringKeyGenerator {

	private static final int DEFAULT_KEY_LENGTH = 32;

	private final BytesKeyGenerator keyGenerator;

	private final Base64.Encoder encoder;

	/**
	 * Creates an instance with keyLength of 32 bytes and standard Base64 encoding.
	 */
	public Base64StringKeyGenerator() {
		this(DEFAULT_KEY_LENGTH);
	}

	/**
	 * Creates an instance with the provided key length in bytes and standard Base64
	 * encoding.
	 * @param keyLength the key length in bytes
	 */
	public Base64StringKeyGenerator(int keyLength) {
		this(Base64.getEncoder(), keyLength);
	}

	/**
	 * Creates an instance with keyLength of 32 bytes and the provided encoder.
	 * @param encoder the encoder to use
	 */
	public Base64StringKeyGenerator(Base64.Encoder encoder) {
		this(encoder, DEFAULT_KEY_LENGTH);
	}

	/**
	 * Creates an instance with the provided key length and encoder.
	 * @param encoder the encoder to use
	 * @param keyLength the key length to use
	 */
	public Base64StringKeyGenerator(Base64.Encoder encoder, int keyLength) {
		if (encoder == null) {
			throw new IllegalArgumentException("encode cannot be null");
		}
		if (keyLength < DEFAULT_KEY_LENGTH) {
			throw new IllegalArgumentException("keyLength must be greater than or equal to" + DEFAULT_KEY_LENGTH);
		}
		this.encoder = encoder;
		this.keyGenerator = KeyGenerators.secureRandom(keyLength);
	}

	@Override
	public String generateKey() {
		byte[] key = this.keyGenerator.generateKey();
		byte[] base64EncodedKey = this.encoder.encode(key);
		return new String(base64EncodedKey);
	}

}
