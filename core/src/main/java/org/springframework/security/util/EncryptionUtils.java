/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.util;

import java.io.UnsupportedEncodingException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

import org.springframework.core.NestedRuntimeException;
import org.springframework.security.core.codec.Base64;
import org.springframework.util.Assert;

/**
 * A static utility class that can encrypt and decrypt text.
 *
 * <p>This class is useful if you have simple needs and wish to use the DESede
 * encryption cipher. More sophisticated requirements will need to use the
 * Java crypto libraries directly.
 *
 * @author Alan Stewart
 * @author Ben Alex
 * @version $Id$
 */
public final class EncryptionUtils {

    /**
     * This is a static class that should not be instantiated.
     */
    private EncryptionUtils() {}

    /**
     * Converts a String into a byte array using UTF-8, falling back to the
     * platform's default character set if UTF-8 fails.
     *
     * @param input the input (required)
     * @return a byte array representation of the input string
     */
    public static byte[] stringToByteArray(String input) {
        Assert.hasLength(input, "Input required");
        try {
            return input.getBytes("UTF-8");
        } catch (UnsupportedEncodingException fallbackToDefault) {
            return input.getBytes();
        }
    }

    /**
     * Converts a byte array into a String using UTF-8, falling back to the
     * platform's default character set if UTF-8 fails.
     *
     * @param byteArray the byte array to convert (required)
     * @return a string representation of the byte array
     */
    public static String byteArrayToString(byte[] byteArray) {
        Assert.notNull(byteArray, "ByteArray required");
        Assert.isTrue(byteArray.length > 0, "ByteArray cannot be empty");
        try {
            return new String(byteArray, "UTF8");
        } catch (final UnsupportedEncodingException e) {
            return new String(byteArray);
        }
    }

    private static byte[] cipher(String key, byte[] passedBytes, int cipherMode) throws EncryptionException {
        try {
            final KeySpec keySpec = new DESedeKeySpec(stringToByteArray(key));
            final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            final Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            final SecretKey secretKey = keyFactory.generateSecret(keySpec);
            cipher.init(cipherMode, secretKey);
            return cipher.doFinal(passedBytes);
        } catch (final Exception e) {
            throw new EncryptionException(e.getMessage(), e);
        }
    }

    /**
     * Encrypts the inputString using the key.
     *
     * @param key at least 24 character long key (required)
     * @param inputString the string to encrypt (required)
     * @return the encrypted version of the inputString
     * @throws EncryptionException in the event of an encryption failure
     */
    public static String encrypt(String key, String inputString) throws EncryptionException {
        isValidKey(key);
        final byte[] cipherText = cipher(key, stringToByteArray(inputString), Cipher.ENCRYPT_MODE);
        return byteArrayToString(Base64.encode(cipherText));
    }

    /**
     * Encrypts the inputBytes using the key.
     *
     * @param key at least 24 character long key (required)
     * @param inputBytes the bytes to encrypt (required)
     * @return the encrypted version of the inputBytes
     * @throws EncryptionException in the event of an encryption failure
     */
    public static byte[] encrypt(String key, byte[] inputBytes) throws EncryptionException {
        isValidKey(key);
        return Base64.encode(cipher(key, inputBytes, Cipher.ENCRYPT_MODE));
    }

    /**
     * Decrypts the inputString using the key.
     *
     * @param key the key used to originally encrypt the string (required)
     * @param inputString the encrypted string (required)
     * @return the decrypted version of inputString
     * @throws EncryptionException in the event of an encryption failure
     */
    public static String decrypt(String key, String inputString) throws EncryptionException {
        Assert.hasText(key, "A key is required to attempt decryption");
        final byte[] cipherText = cipher(key, Base64.decode(stringToByteArray(inputString)), Cipher.DECRYPT_MODE);
        return byteArrayToString(cipherText);
    }

    /**
     * Decrypts the inputBytes using the key.
     *
     * @param key the key used to originally encrypt the string (required)
     * @param inputBytes the encrypted bytes (required)
     * @return the decrypted version of inputBytes
     * @throws EncryptionException in the event of an encryption failure
     */
    public static byte[] decrypt(String key, byte[] inputBytes) throws EncryptionException {
        Assert.hasText(key, "A key is required to attempt decryption");
        return cipher(key, Base64.decode(inputBytes), Cipher.DECRYPT_MODE);
    }

    private static void isValidKey(String key) {
        Assert.hasText(key, "A key to perform the encryption is required");
        Assert.isTrue(key.length() >= 24, "Key must be at least 24 characters long");
    }

    public static class EncryptionException extends NestedRuntimeException {
        private static final long serialVersionUID = 1L;

        public EncryptionException(String message, Throwable t) {
            super(message, t);
        }

        public EncryptionException(String message) {
            super(message);
        }
    }
}
