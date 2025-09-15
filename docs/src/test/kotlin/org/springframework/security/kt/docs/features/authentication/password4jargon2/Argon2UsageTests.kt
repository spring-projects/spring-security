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
package org.springframework.security.kt.docs.features.authentication.password4jargon2

import com.password4j.Argon2Function
import com.password4j.types.Argon2
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.crypto.password4j.Argon2Password4jPasswordEncoder

/**
 * @author Rob Winch
 */
class Argon2UsageTests {

    @Test
    fun defaultParams() {
        // tag::default-params[]
        val encoder: PasswordEncoder = Argon2Password4jPasswordEncoder()
        val result = encoder.encode("myPassword")
        assertThat(encoder.matches("myPassword", result)).isTrue()
        // end::default-params[]
    }

    @Test
    fun customParameters() {
        // tag::custom-params[]
        val argon2Fn = Argon2Function.getInstance(
            65536, 3, 4, 32,
            Argon2.ID
        )
        val encoder: PasswordEncoder = Argon2Password4jPasswordEncoder(argon2Fn)
        val result = encoder.encode("myPassword")
        assertThat(encoder.matches("myPassword", result)).isTrue()
        // end::custom-params[]
    }
}
