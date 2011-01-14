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

import static org.springframework.security.crypto.util.CipherUtils.doFinal;
import static org.springframework.security.crypto.util.CipherUtils.initCipher;
import static org.springframework.security.crypto.util.CipherUtils.newCipher;
import static org.springframework.security.crypto.util.CipherUtils.newSecretKey;
import static org.springframework.security.crypto.util.EncodingUtils.concatenate;
import static org.springframework.security.crypto.util.EncodingUtils.subArray;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;

/**
 * A general purpose encryptor for password-based encryption (PBEwith{prf}and{encryption} algorithms).
 * Prepends a random salt to each encrypted value to aid in the prevention of password compromise with the aid of a dictionary/rainbow table.
 * The salt allows the same secret key to be used for multiple encryption operations.
 * The password should be not be shared.
 * Note: {prf} = Pseudo random function e.g. MD5; {encryption} = Encryption method e.g. DES or AES.
 * @author Keith Donald
 */
final class PasswordBasedBytesEncryptor implements BytesEncryptor {

    private final SecretKey secretKey;

    private final BytesKeyGenerator saltGenerator;

    private final Cipher encryptor;

    private final Cipher decryptor;

    public PasswordBasedBytesEncryptor(String algorithm, String password) {
        secretKey = newSecretKey(algorithm, password);
        saltGenerator = KeyGenerators.secureRandom();
        encryptor = newCipher(algorithm);
        decryptor = newCipher(algorithm);
    }

    public byte[] encrypt(byte[] bytes) {
        byte[] salt = saltGenerator.generateKey();
        byte[] encrypted;
        synchronized (encryptor) {
            initCipher(encryptor, Cipher.ENCRYPT_MODE, secretKey, salt, 1024);
            encrypted = doFinal(encryptor, bytes);
        }
        return concatenate(salt, encrypted);
    }

    public byte[] decrypt(byte[] encryptedBytes) {
        byte[] salt = saltPart(encryptedBytes);
        byte[] decrypted;
        synchronized (decryptor) {
            initCipher(decryptor, Cipher.DECRYPT_MODE, secretKey, salt, 1024);
            decrypted = doFinal(decryptor, cipherPart(encryptedBytes, salt));
        }
        return decrypted;
    }

    private byte[] saltPart(byte[] encrypted) {
        return subArray(encrypted, 0, saltGenerator.getKeyLength());
    }

    private byte[] cipherPart(byte[] encrypted, byte[] salt) {
        return subArray(encrypted, salt.length, encrypted.length);
    }

}