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
package org.springframework.security.crypto.encrypt;

/**
 * Factory for commonly used encryptors.
 * Defines the public API for constructing {@link BytesEncryptor} and {@link TextEncryptor} implementations.
 * @author Keith Donald
 */
public class Encryptors {

    /**
     * Creates a standard password-based bytes encryptor.
     * Uses MD5 PRF hashing with 1024 iterations and DES-based encryption.
     * Salts each encrypted value to ensure it will be unique.
     * TODO - switch standard algorithm from DES to AES.  Switch hashing to SHA-1 from MD5.
     * @param password the password used to generate the encryptor's secret key; should not be shared
     */
    public static BytesEncryptor standard(String password) {
        return new PasswordBasedBytesEncryptor(PBE_MD5_DES_ALGORITHM, password);
    }

    /**
     * Creates a text encryptor that uses standard password-based encryption.
     * Encrypted text is hex-encoded.
     * @param password the password used to generate the encryptor's secret key; should not be shared
     */
    public static TextEncryptor text(String password) {
        return new HexEncodingTextEncryptor(standard(password));
    }

    /**
     * Creates an encryptor for queryable text strings that uses standard password-based encryption.
     * The hex-encoded salt string provided should be random and is used to protect against password dictionary attacks.
     * Does not salt each encrypted value so an encrypted value may be queried against.
     * Encrypted text is hex-encoded.
     * @param password the password used to generate the encryptor's secret key; should not be shared
     * @param salt an hex-encoded, random, site-global salt value to use to initialize the cipher
     */
    public static TextEncryptor queryableText(String password, String salt) {
        return new QueryableTextEncryptor(PBE_MD5_DES_ALGORITHM, password, salt);
    }

    /**
     * Creates a text encrypter that performs no encryption.
     * Useful for test environments where working with plain text strings is desired for simplicity.
     */
    public static TextEncryptor noOpText() {
        return NO_OP_TEXT_INSTANCE;
    }

    // internal helpers

    private Encryptors() {
    }

    private static final String PBE_MD5_DES_ALGORITHM = "PBEWithMD5AndDES";

    private static final TextEncryptor NO_OP_TEXT_INSTANCE = new NoOpTextEncryptor();

    private static final class NoOpTextEncryptor implements TextEncryptor {

        public String encrypt(String text) {
            return text;
        }

        public String decrypt(String encryptedText) {
            return encryptedText;
        }

    }

}