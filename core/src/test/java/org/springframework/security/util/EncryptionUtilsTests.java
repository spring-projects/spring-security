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

import junit.framework.TestCase;

import org.springframework.security.util.EncryptionUtils.EncryptionException;

/**
 * JUnit tests for EncryptionUtils.
 *
 * @author Alan Stewart
 * @author Ben Alex
 */
@SuppressWarnings("deprecation")
public class EncryptionUtilsTests extends TestCase {
    private final static String STRING_TO_ENCRYPT = "Alan K Stewart";
    private final static String ENCRYPTION_KEY = "123456789012345678901234567890";

    public void testEncryptsUsingDESEde() throws EncryptionException {
        final String encryptedString = EncryptionUtils.encrypt(ENCRYPTION_KEY, STRING_TO_ENCRYPT);
        assertEquals("3YIE8sIbaEoqGZZrHamFGQ==", encryptedString);
    }

    public void testEncryptByteArrayUsingDESEde() {
        final byte[] encryptedArray = EncryptionUtils.encrypt(ENCRYPTION_KEY, EncryptionUtils.stringToByteArray(STRING_TO_ENCRYPT));
        assertEquals("3YIE8sIbaEoqGZZrHamFGQ==", EncryptionUtils.byteArrayToString(encryptedArray));
    }

    public void testEncryptionKeyCanContainLetters() throws EncryptionException {
        final String encryptedString = EncryptionUtils.encrypt("ASDF asdf 1234 8983 jklasdf J2Jaf8", STRING_TO_ENCRYPT);
        assertEquals("v4+DQoClx6qm5tJwBcRrkw==", encryptedString);
    }

    public void testDecryptsUsingDESEde() throws EncryptionException {
        final String encryptedString = "3YIE8sIbaEoqGZZrHamFGQ==";
        final String decryptedString = EncryptionUtils.decrypt(ENCRYPTION_KEY, encryptedString);
        assertEquals(STRING_TO_ENCRYPT, decryptedString);
    }

    public void testDecryptByteArrayUsingDESEde() {
        final byte[] encrypted = EncryptionUtils.stringToByteArray("3YIE8sIbaEoqGZZrHamFGQ==");
        final byte[] decrypted = EncryptionUtils.decrypt(ENCRYPTION_KEY, encrypted);
        assertEquals(STRING_TO_ENCRYPT, EncryptionUtils.byteArrayToString(decrypted));
    }

    public void testFailEncryptWithNullEncryptionKey() {
        try {
            EncryptionUtils.encrypt(null, STRING_TO_ENCRYPT);
            fail();
        } catch (IllegalArgumentException e) {
            assertTrue(true);
        }
    }

    public void testFailEncryptWithEmptyEncryptionKey() {
        try {
            EncryptionUtils.encrypt("", STRING_TO_ENCRYPT);
            fail();
        } catch (IllegalArgumentException e) {
            assertTrue(true);
        }
    }

    public void teastFailEncryptWithShortEncryptionKey() {
        try {
            EncryptionUtils.encrypt("01234567890123456789012", STRING_TO_ENCRYPT);
            fail();
        } catch (IllegalArgumentException e) {
            assertTrue(true);
        }
    }

    public void testFailDecryptWithEmptyString() {
        try {
            EncryptionUtils.decrypt(ENCRYPTION_KEY, "");
            fail();
        } catch (IllegalArgumentException e) {
            assertTrue(true);
        }
    }

    public void testFailEncryptWithEmptyString() {
        try {
            EncryptionUtils.encrypt(ENCRYPTION_KEY, "");
            fail();
        } catch (IllegalArgumentException e) {
            assertTrue(true);
        }
    }

    public void testFailEncryptWithNullString() {
        try {
            EncryptionUtils.encrypt(ENCRYPTION_KEY, (String) null);
            fail();
        } catch (IllegalArgumentException e) {
            assertTrue(true);
        }
    }

    public void testEncryptAndDecrypt() throws EncryptionException {
        final String stringToEncrypt = "Alan Stewart";
        final String encryptedString = EncryptionUtils.encrypt(ENCRYPTION_KEY, stringToEncrypt);
        final String decryptedString = EncryptionUtils.decrypt(ENCRYPTION_KEY, encryptedString);
        assertEquals(stringToEncrypt, decryptedString);
    }
}
