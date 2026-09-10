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

package org.springframework.security.kt.docs.features.integrations.springsecuritycryptoencryptiontext

import org.junit.jupiter.api.Test
import org.springframework.security.crypto.encrypt.AesCbcBytesEncryptor
import org.springframework.security.crypto.keygen.KeyGenerators

class CryptoEncryptionTests {

    // tag::aes-cbc-bytes-encryptor[]
    @Test
    fun aesCbcBytesEncryptor() {
        val salt = KeyGenerators.string().generateKey()
        AesCbcBytesEncryptor.withPassword("password", salt).build()
    }
    // end::aes-cbc-bytes-encryptor[]

}
