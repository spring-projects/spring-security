/*
 * Copyright 2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.crypto.encrypt;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * Static helper for working with the Cipher API.
 * @author Keith Donald
 */
class CipherUtils {

    /**
     * Generates a SecretKey.
     */
    public static SecretKey newSecretKey(String algorithm, String password) {
        return newSecretKey(algorithm, new PBEKeySpec(password.toCharArray()));
    }

    /**
     * Generates a SecretKey.
     */
    public static SecretKey newSecretKey(String algorithm, PBEKeySpec keySpec) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
            return factory.generateSecret(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Not a valid encryption algorithm", e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException("Not a valid secret key", e);
        }
    }

    /**
     * Constructs a new Cipher.
     */
    public static Cipher newCipher(String algorithm) {
        try {
            return Cipher.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Not a valid encryption algorithm", e);
        } catch (NoSuchPaddingException e) {
            throw new IllegalStateException("Should not happen", e);
        }
    }

    /**
     * Initializes the Cipher for use.
     */
    public static <T extends AlgorithmParameterSpec> T getParameterSpec(Cipher cipher, Class<T> parameterSpecClass) {
        try {
            return cipher.getParameters().getParameterSpec(parameterSpecClass);
        } catch (InvalidParameterSpecException e) {
            throw new IllegalArgumentException("Unable to access parameter", e);
        }
    }

    /**
     * Initializes the Cipher for use.
     */
    public static void initCipher(Cipher cipher, int mode, SecretKey secretKey) {
        initCipher(cipher, mode, secretKey, null);
    }

    /**
     * Initializes the Cipher for use.
     */
    public static void initCipher(Cipher cipher, int mode, SecretKey secretKey, byte[] salt, int iterationCount) {
        initCipher(cipher, mode, secretKey, new PBEParameterSpec(salt, iterationCount));
    }

    /**
     * Initializes the Cipher for use.
     */
    public static void initCipher(Cipher cipher, int mode, SecretKey secretKey, AlgorithmParameterSpec parameterSpec) {
        try {
            if (parameterSpec != null) {
                cipher.init(mode, secretKey, parameterSpec);
            } else {
                cipher.init(mode, secretKey);
            }
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("Unable to initialize due to invalid secret key", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Unable to initialize due to invalid decryption parameter spec", e);
        }
    }

    /**
     * Invokes the Cipher to perform encryption or decryption (depending on the initialized mode).
     */
    public static byte[] doFinal(Cipher cipher, byte[] input) {
        try {
            return cipher.doFinal(input);
        } catch (IllegalBlockSizeException e) {
            throw new IllegalStateException("Unable to invoke Cipher due to illegal block size", e);
        } catch (BadPaddingException e) {
            throw new IllegalStateException("Unable to invoke Cipher due to bad padding", e);
        }
    }

    private CipherUtils() {
    }

}
