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
package org.springframework.security.crypto.password;

import static org.springframework.security.crypto.util.EncodingUtils.concatenate;
import static org.springframework.security.crypto.util.EncodingUtils.hexDecode;
import static org.springframework.security.crypto.util.EncodingUtils.hexEncode;
import static org.springframework.security.crypto.util.EncodingUtils.subArray;
import static org.springframework.security.crypto.util.EncodingUtils.utf8Encode;

import java.util.Arrays;

import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.util.Digester;

/**
 * A standard PasswordEncoder implementation that uses SHA-256 1024 iteration hashing with 8-byte random salting.
 * @author Keith Donald
 */
public final class StandardPasswordEncoder implements PasswordEncoder {

    private final Digester digester;

    private final byte[] secret;

    private final BytesKeyGenerator saltGenerator;

    /**
     * Constructs a standard password encoder.
     * @param secret the secret key used in the encoding process (should not be shared)
     */
    public StandardPasswordEncoder(String secret) {
        this("SHA-256", "SUN", secret);
    }

    public String encode(String rawPassword) {
        return encode(rawPassword, saltGenerator.generateKey());
    }

    public boolean matches(String rawPassword, String encodedPassword) {
        byte[] digested = decode(encodedPassword);
        byte[] salt = subArray(digested, 0, saltGenerator.getKeyLength());
        return matches(digested, digest(rawPassword, salt));
    }

    // internal helpers

    private StandardPasswordEncoder(String algorithm, String provider, String secret) {
        this.digester = new Digester(algorithm, provider);
        this.secret = utf8Encode(secret);
        this.saltGenerator = KeyGenerators.secureRandom();
    }

    private String encode(String rawPassword, byte[] salt) {
        byte[] digest = digest(rawPassword, salt);
        return hexEncode(digest);
    }

    private byte[] digest(String rawPassword, byte[] salt) {
        byte[] digest = digester.digest(concatenate(salt, secret, utf8Encode(rawPassword)));
        return concatenate(salt, digest);
    }

    private byte[] decode(String encodedPassword) {
        return hexDecode(encodedPassword);
    }

    private boolean matches(byte[] expected, byte[] actual) {
        return Arrays.equals(expected, actual);
    }

}