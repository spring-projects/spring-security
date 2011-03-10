/*
 * Copyright 2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.crypto.util;

import java.io.UnsupportedEncodingException;

/**
 * Static helper for encoding data.
 * @author Keith Donald
 */
public class EncodingUtils {

    /**
     * Encode the byte array into a hex String.
     */
    public static String hexEncode(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        char[] digits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
        for (int i = 0; i < bytes.length; ++i) {
            byte b = bytes[i];
            result.append(digits[(b & 0xf0) >> 4]);
            result.append(digits[b & 0x0f]);
        }
        return result.toString();
    }

    /**
     * Decode the hex String into a byte array.
     */
    public static byte[] hexDecode(String s) {
        int len = s.length();
        byte[] r = new byte[len / 2];
        for (int i = 0; i < r.length; i++) {
            int digit1 = s.charAt(i * 2), digit2 = s.charAt(i * 2 + 1);
            if ((digit1 >= '0') && (digit1 <= '9'))  {
                digit1 -= '0';
            } else if ((digit1 >= 'a') && (digit1 <= 'f')) {
                digit1 -= 'a' - 10;
            }
            if ((digit2 >= '0') && (digit2 <= '9')) {
                digit2 -= '0';
            } else if ((digit2 >= 'a') && (digit2 <= 'f')) {
                digit2 -= 'a' - 10;
            }
            r[i] = (byte) ((digit1 << 4) + digit2);
        }
        return r;
    }

    /**
     * Get the bytes of the String in UTF-8 encoded form.
     */
    public static byte[] utf8Encode(String string) {
        try {
            return string.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw encodingException(e);
        }
    }

    /**
     * Decode the bytes in UTF-8 form into a String.
     */
    public static String utf8Decode(byte[] bytes) {
        try {
            return new String(bytes, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw encodingException(e);
        }
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

    private EncodingUtils() {
    }

    private static RuntimeException encodingException(UnsupportedEncodingException e) {
        return new IllegalStateException("UTF-8 is not an available char set", e);
    }

}
