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

package org.springframework.security.crypto.codec;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * UTF-8 Charset encoder/decoder.
 * <p>
 * For internal use only.
 *
 * @author Luke Taylor
 */
public final class Utf8 {

	private static final Charset CHARSET = StandardCharsets.UTF_8;

	/**
	 * Get the bytes of the String in UTF-8 encoded form.
	 */
	public static byte[] encode(CharSequence string) {
		try {
			ByteBuffer bytes = CHARSET.newEncoder().encode(CharBuffer.wrap(string));
			byte[] bytesCopy = new byte[bytes.limit()];
			System.arraycopy(bytes.array(), 0, bytesCopy, 0, bytes.limit());

			return bytesCopy;
		}
		catch (CharacterCodingException ex) {
			throw new IllegalArgumentException("Encoding failed", ex);
		}
	}

	/**
	 * Decode the bytes in UTF-8 form into a String.
	 */
	public static String decode(byte[] bytes) {
		try {
			return CHARSET.newDecoder().decode(ByteBuffer.wrap(bytes)).toString();
		}
		catch (CharacterCodingException ex) {
			throw new IllegalArgumentException("Decoding failed", ex);
		}
	}

}
