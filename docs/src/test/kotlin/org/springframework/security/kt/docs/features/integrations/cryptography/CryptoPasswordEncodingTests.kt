/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.kt.docs.features.integrations.cryptography

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder

class CryptoPasswordEncodingTests {

    // tag::bcrypt[]
    @Test
    fun bcryptPasswordEncoder() {
        // Create an encoder with strength 16
        val encoder = BCryptPasswordEncoder(16)
        val result: String = encoder.encode("myPassword")
        assertTrue(encoder.matches("myPassword", result))
    }
    // end::bcrypt[]

    // tag::pbkdf2[]
    @Test
    fun pbkdf2PasswordEncoder() {
        // Create an encoder with all the defaults
        val encoder = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8()
        val result: String = encoder.encode("myPassword")
        assertTrue(encoder.matches("myPassword", result))
    }
    // end::pbkdf2[]

}
