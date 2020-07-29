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

/**
 * Hex data encoder. Converts byte arrays (such as those obtained from message digests)
 * into hexadecimal string representation.
 * <p>
 * For internal use only.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public final class Hex {

	private static final char[] HEX = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e',
			'f' };

	private Hex() {
	}

	public static char[] encode(byte[] bytes) {
		final int nBytes = bytes.length;
		char[] result = new char[2 * nBytes];

		int j = 0;
		for (byte aByte : bytes) {
			// Char for top 4 bits
			result[j++] = HEX[(0xF0 & aByte) >>> 4];
			// Bottom 4
			result[j++] = HEX[(0x0F & aByte)];
		}

		return result;
	}

	public static byte[] decode(CharSequence s) {
		int nChars = s.length();

		if (nChars % 2 != 0) {
			throw new IllegalArgumentException("Hex-encoded string must have an even number of characters");
		}

		byte[] result = new byte[nChars / 2];

		for (int i = 0; i < nChars; i += 2) {
			int msb = Character.digit(s.charAt(i), 16);
			int lsb = Character.digit(s.charAt(i + 1), 16);

			if (msb < 0 || lsb < 0) {
				throw new IllegalArgumentException(
						"Detected a Non-hex character at " + (i + 1) + " or " + (i + 2) + " position");
			}
			result[i / 2] = (byte) ((msb << 4) | lsb);
		}
		return result;
	}

}
