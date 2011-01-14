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
package org.springframework.security.crypto.util;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

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
public class CipherUtils {

    /**
     * Generates a SecretKey.
     */
    public static SecretKey newSecretKey(String algorithm, String secret) {
        try {
            PBEKeySpec pbeKeySpec = new PBEKeySpec(secret.toCharArray());
            SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
            return factory.generateSecret(pbeKeySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Not a valid encryption algorithm", e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException("Not a valid secert key", e);
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
    public static void initCipher(Cipher cipher, int mode, SecretKey secretKey, byte[] salt, int iterationCount) {
        try {
            cipher.init(mode, secretKey, new PBEParameterSpec(salt, iterationCount));
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
