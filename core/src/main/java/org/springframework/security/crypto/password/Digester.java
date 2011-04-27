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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * Helper for working with the MessageDigest API.
 *
 * Performs 1024 iterations of the hashing algorithm per digest to aid in protecting against brute force attacks.
 *
 * @author Keith Donald
 * @author Luke Taylor
 */
class Digester {

    private final MessageDigest messageDigest;

    private final int iterations;

    /**
     * Create a new Digester.
     * @param algorithm the digest algorithm; for example, "SHA-1" or "SHA-256".
     */
    public Digester(String algorithm, int iterations) {
        try {
            messageDigest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("No such hashing algorithm", e);
        }

        this.iterations = iterations;
    }

    public byte[] digest(byte[] value) {
        synchronized (messageDigest) {
            for (int i = 0; i < (iterations - 1); i++) {
                value = invokeDigest(value);
            }
            return messageDigest.digest(value);
        }
    }

    private byte[] invokeDigest(byte[] value) {
        messageDigest.reset();
        return messageDigest.digest(value);
    }

}
