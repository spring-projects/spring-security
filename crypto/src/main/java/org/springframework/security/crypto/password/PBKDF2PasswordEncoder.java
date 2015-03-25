/*
 * Copyright 2013 the original author or authors.
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

import org.springframework.security.crypto.codec.Utf8;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;

import static org.springframework.security.crypto.util.EncodingUtils.concatenate;

/**
 * A {@code PasswordEncoder} implementation that uses PBKDF2 with a configurable number of iterations and a
 * random 8-byte random salt value.
 * <p>
 * The width of the output hash can also be configured.
 * <p>
 * The algorithm is invoked on the concatenated bytes of the salt, secret and password.
 *
 * @author Rob Worsnop
 */
public class PBKDF2PasswordEncoder extends AbstractPasswordEncoder{
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final int DEFAULT_HASH_WIDTH = 160;
    private static final int DEFAULT_ITERATIONS = 1024;

    private final byte[] secret;
    private final int hashWidth;
    private final int iterations;

    /**
     * Constructs a PBKDF2 password encoder with no additional secret value. There will be 1024 iterations
     * and a hash width of 160.
     */
    public PBKDF2PasswordEncoder() {
        this("");
    }

    /**
     * Constructs a standard password encoder with a secret value which is also included in the
     * password hash. There will be 1024 iterations and a hash width of 160.
     *
     * @param secret the secret key used in the encoding process (should not be shared)
     */
    public PBKDF2PasswordEncoder(CharSequence secret) {
        this(secret, DEFAULT_ITERATIONS, DEFAULT_HASH_WIDTH);
    }

    /**
     * Constructs a standard password encoder with a secret value as well as iterations and hash.
     *
     * @param secret
     * @param iterations
     * @param hashWidth
     */
    public PBKDF2PasswordEncoder(CharSequence secret, int iterations, int hashWidth) {
        this.secret = Utf8.encode(secret);
        this.iterations = iterations;
        this.hashWidth = hashWidth;
    }

    @Override
    protected byte[] encode(CharSequence rawPassword, byte[] salt) {
        try{
            PBEKeySpec spec = new PBEKeySpec(rawPassword.toString().toCharArray(), concatenate(salt,secret), iterations, hashWidth);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            return concatenate(salt, skf.generateSecret(spec).getEncoded());
        } catch (GeneralSecurityException e){
            throw new IllegalStateException("Could not create hash", e);
        }
    }
}
