/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.core.token;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.springframework.security.crypto.codec.Hex;

/**
 * Provides SHA512 digest methods.
 *
 * <p>
 * Based on Commons Codec, which does not presently provide SHA512 support.
 * </p>
 *
 * @author Ben Alex
 * @since 2.0.1
 *
 */
public abstract class Sha512DigestUtils {

	/**
	 * Returns an SHA digest.
	 *
	 * @return An SHA digest instance.
	 * @throws RuntimeException when a {@link java.security.NoSuchAlgorithmException} is
	 * caught.
	 */
	private static MessageDigest getSha512Digest() {
		try {
			return MessageDigest.getInstance("SHA-512");
		}
		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	/**
	 * Calculates the SHA digest and returns the value as a <code>byte[]</code>.
	 *
	 * @param data Data to digest
	 * @return SHA digest
	 */
	public static byte[] sha(byte[] data) {
		return getSha512Digest().digest(data);
	}

	/**
	 * Calculates the SHA digest and returns the value as a <code>byte[]</code>.
	 *
	 * @param data Data to digest
	 * @return SHA digest
	 */
	public static byte[] sha(String data) {
		return sha(data.getBytes());
	}

	/**
	 * Calculates the SHA digest and returns the value as a hex string.
	 *
	 * @param data Data to digest
	 * @return SHA digest as a hex string
	 */
	public static String shaHex(byte[] data) {
		return new String(Hex.encode(sha(data)));
	}

	/**
	 * Calculates the SHA digest and returns the value as a hex string.
	 *
	 * @param data Data to digest
	 * @return SHA digest as a hex string
	 */
	public static String shaHex(String data) {
		return new String(Hex.encode(sha(data)));
	}

}
