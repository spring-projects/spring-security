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

import static org.springframework.security.crypto.util.EncodingUtils.hexDecode;
import static org.springframework.security.crypto.util.EncodingUtils.hexEncode;
import static org.springframework.security.crypto.util.EncodingUtils.utf8Decode;
import static org.springframework.security.crypto.util.EncodingUtils.utf8Encode;

/**
 * Delegates to an {@link BytesEncryptor} to encrypt text strings.
 * Raw text strings are UTF-8 encoded before being passed to the encryptor.
 * Encrypted strings are returned hex-encoded.
 * @author Keith Donald
 */
final class HexEncodingTextEncryptor implements TextEncryptor {

    private final BytesEncryptor encryptor;

    public HexEncodingTextEncryptor(BytesEncryptor encryptor) {
        this.encryptor = encryptor;
    }

    public String encrypt(String text) {
        return hexEncode(encryptor.encrypt(utf8Encode(text)));
    }

    public String decrypt(String encryptedText) {
        return utf8Decode(encryptor.decrypt(hexDecode(encryptedText)));
    }

}
