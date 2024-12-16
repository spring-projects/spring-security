/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.webauthn.api;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import org.springframework.util.Assert;

/**
 * An object representation of byte[].
 *
 * @author Rob Winch
 * @since 6.4
 */
public final class Bytes {

	private static final SecureRandom RANDOM = new SecureRandom();

	private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

	private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

	private final byte[] bytes;

	/**
	 * Creates a new instance
	 * @param bytes the raw base64UrlString that will be encoded.
	 */
	public Bytes(byte[] bytes) {
		Assert.notNull(bytes, "bytes cannot be null");
		this.bytes = bytes;
	}

	/**
	 * Gets the raw bytes.
	 * @return the bytes
	 */
	public byte[] getBytes() {
		return Arrays.copyOf(this.bytes, this.bytes.length);
	}

	/**
	 * Gets the bytes as Base64 URL encoded String.
	 * @return
	 */
	public String toBase64UrlString() {
		return ENCODER.encodeToString(getBytes());
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof Bytes that) {
			return that.toBase64UrlString().equals(toBase64UrlString());
		}
		return false;
	}

	@Override
	public int hashCode() {
		return toBase64UrlString().hashCode();
	}

	public String toString() {
		return "Bytes[" + toBase64UrlString() + "]";
	}

	/**
	 * Creates a secure random {@link Bytes} with random bytes and sufficient entropy.
	 * @return a new secure random generated {@link Bytes}
	 */
	public static Bytes random() {
		byte[] bytes = new byte[32];
		RANDOM.nextBytes(bytes);
		return new Bytes(bytes);
	}

	/**
	 * Creates a new instance from a base64 url string.
	 * @param base64UrlString the base64 url string
	 * @return the {@link Bytes}
	 */
	public static Bytes fromBase64(String base64UrlString) {
		byte[] bytes = DECODER.decode(base64UrlString);
		return new Bytes(bytes);
	}

}
