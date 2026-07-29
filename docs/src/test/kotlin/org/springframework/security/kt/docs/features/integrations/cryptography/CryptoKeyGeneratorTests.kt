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

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.security.crypto.keygen.KeyGenerators

class CryptoKeyGeneratorTests {

    // tag::bytes-key-generator[]
    @Test
    fun bytesKeyGenerator() {
        val generator = KeyGenerators.secureRandom()
        val key = generator.generateKey()
        assertThat(key).hasSize(8)
    }
    // end::bytes-key-generator[]

    // tag::bytes-key-generator-custom-length[]
    @Test
    fun bytesKeyGeneratorCustomLength() {
        KeyGenerators.secureRandom(16)
    }
    // end::bytes-key-generator-custom-length[]

    // tag::bytes-key-generator-shared[]
    @Test
    fun bytesKeyGeneratorShared() {
        KeyGenerators.shared(16)
    }
    // end::bytes-key-generator-shared[]

    // tag::string-key-generator[]
    @Test
    fun stringKeyGenerator() {
        KeyGenerators.string()
    }
    // end::string-key-generator[]

}
