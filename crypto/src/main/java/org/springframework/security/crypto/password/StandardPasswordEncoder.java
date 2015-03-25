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

import org.springframework.security.crypto.codec.Utf8;

import static org.springframework.security.crypto.util.EncodingUtils.concatenate;

/**
 * A standard {@code PasswordEncoder} implementation that uses SHA-256 hashing with 1024 iterations and a
 * random 8-byte random salt value. It uses an additional system-wide secret value to provide additional protection.
 * <p>
 * The digest algorithm is invoked on the concatenated bytes of the salt, secret and password.
 * <p>
 * If you are developing a new system, {@link org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder} is
 * a better choice both in terms of security and interoperability with other languages.
 *
 * @author Keith Donald
 * @author Luke Taylor
 * @author Rob Worsnop
 */
public final class StandardPasswordEncoder extends AbstractPasswordEncoder {

    private final Digester digester;

    private final byte[] secret;

    /**
     * Constructs a standard password encoder with no additional secret value.
     */
    public StandardPasswordEncoder() {
        this("");
    }

    /**
     * Constructs a standard password encoder with a secret value which is also included in the
     * password hash.
     *
     * @param secret the secret key used in the encoding process (should not be shared)
     */
    public StandardPasswordEncoder(CharSequence secret) {
        this("SHA-256", secret);
    }

    @Override
    protected byte[] encode(CharSequence rawPassword, byte[] salt) {
        return digester.digest(concatenate(salt, secret, Utf8.encode(rawPassword)));
    }


    // internal helpers

    private StandardPasswordEncoder(String algorithm, CharSequence secret) {
        this.digester = new Digester(algorithm, DEFAULT_ITERATIONS);
        this.secret = Utf8.encode(secret);
    }

    private static final int DEFAULT_ITERATIONS = 1024;

}
