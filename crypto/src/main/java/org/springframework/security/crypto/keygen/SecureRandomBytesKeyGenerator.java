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
package org.springframework.security.crypto.keygen;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

/**
 * A KeyGenerator that uses SecureRandom to generate byte array-based keys.
 * Defaults to 8 byte keys produced by the SHA1PRNG algorithm developed by the Sun Provider.
 * @author Keith Donald
 */
final class SecureRandomBytesKeyGenerator implements BytesKeyGenerator {

    private final SecureRandom random;

    private final int keyLength;

    /**
     * Creates a secure random key generator using the defaults.
     */
    public SecureRandomBytesKeyGenerator() {
        this(DEFAULT_ALGORITHM, DEFAULT_PROVIDER, DEFAULT_KEY_LENGTH);
    }

    /**
     * Creates a secure random key generator with a custom key length.
     */
    public SecureRandomBytesKeyGenerator(int keyLength) {
        this(DEFAULT_ALGORITHM, DEFAULT_PROVIDER, keyLength);
    }

    public int getKeyLength() {
        return keyLength;
    }

    public byte[] generateKey() {
        byte[] bytes = new byte[keyLength];
        random.nextBytes(bytes);
        return bytes;
    }

    // internal helpers

    /**
     * Creates a secure random key generator that is fully customized.
     */
    private SecureRandomBytesKeyGenerator(String algorithm, String provider, int keyLength) {
        this.random = createSecureRandom(algorithm, provider, keyLength);
        this.keyLength = keyLength;
    }

    private SecureRandom createSecureRandom(String algorithm, String provider, int keyLength) {
        try {
            SecureRandom random = SecureRandom.getInstance(algorithm, provider);
            random.setSeed(random.generateSeed(keyLength));
            return random;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Not a supported SecureRandom key generation algorithm", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalArgumentException("Not a supported SecureRandom key provider", e);
        }
    }

    private static final String DEFAULT_ALGORITHM = "SHA1PRNG";

    private static final String DEFAULT_PROVIDER = "SUN";

    private static final int DEFAULT_KEY_LENGTH = 8;

}