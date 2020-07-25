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
package org.springframework.security.crypto.util;

/**
 * Static helper for encoding data.
 * <p>
 * For internal use only.
 *
 * @author Keith Donald
 */
public final class EncodingUtils {

	private EncodingUtils() {
	}

	/**
	 * Combine the individual byte arrays into one array.
	 */
	public static byte[] concatenate(byte[]... arrays) {
		int length = 0;
		for (byte[] array : arrays) {
			length += array.length;
		}
		byte[] newArray = new byte[length];
		int destPos = 0;
		for (byte[] array : arrays) {
			System.arraycopy(array, 0, newArray, destPos, array.length);
			destPos += array.length;
		}
		return newArray;
	}

	/**
	 * Extract a sub array of bytes out of the byte array.
	 * @param array the byte array to extract from
	 * @param beginIndex the beginning index of the sub array, inclusive
	 * @param endIndex the ending index of the sub array, exclusive
	 */
	public static byte[] subArray(byte[] array, int beginIndex, int endIndex) {
		int length = endIndex - beginIndex;
		byte[] subarray = new byte[length];
		System.arraycopy(array, beginIndex, subarray, 0, length);
		return subarray;
	}

}
