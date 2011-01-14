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
import static org.springframework.security.crypto.util.EncodingUtils.hexDecode;
import static org.springframework.security.crypto.util.EncodingUtils.hexEncode;
import static org.springframework.security.crypto.util.EncodingUtils.utf8Decode;
import static org.springframework.security.crypto.util.EncodingUtils.utf8Encode;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * A text encryptor that applies password-based MD5 plus DES symmetric key encryption.
 * Designed to be used to encrypt fields that are queryable; for example, an indexed field such as an OAuth apiKey.
 * Requires a random site-global salt to protect against password dictionary attacks.
 * Does not salt on each {@link #encrypt(String)} operation to allow the encrypted field to be queried.
 * @author Keith Donald
 */
final class QueryableTextEncryptor implements TextEncryptor {

    private final Cipher encryptor;

    private final Cipher decryptor;

    public QueryableTextEncryptor(String algorithm, String password, String salt) {
        byte[] saltBytes = hexDecode(salt);
        SecretKey secretKey = newSecretKey(algorithm, password);
        encryptor = newCipher(algorithm);
        initCipher(encryptor, Cipher.ENCRYPT_MODE, secretKey, saltBytes, 1000);
        decryptor = newCipher(algorithm);
        initCipher(decryptor, Cipher.DECRYPT_MODE, secretKey, saltBytes, 1000);
    }

    public String encrypt(String text) {
        return hexEncode(doFinal(encryptor, utf8Encode(text)));
    }

    public String decrypt(String encryptedText) {
        return utf8Decode(doFinal(decryptor, hexDecode(encryptedText)));
    }

}
