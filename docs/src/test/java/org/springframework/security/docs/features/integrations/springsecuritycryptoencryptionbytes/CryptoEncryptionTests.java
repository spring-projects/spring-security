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

package org.springframework.security.docs.features.integrations.springsecuritycryptoencryptionbytes;

import org.junit.jupiter.api.Test;

import org.springframework.security.crypto.encrypt.AesCbcBytesEncryptor;
import org.springframework.security.crypto.encrypt.AesGcmBytesEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;

import static org.assertj.core.api.Assertions.assertThat;

class CryptoEncryptionTests {

	// tag::bytes-encryptor[]
	@Test
	void bytesEncryptor() {
		String salt = KeyGenerators.string().generateKey();
		AesGcmBytesEncryptor.withPassword("password", salt).build();
	}
	// end::bytes-encryptor[]

	// tag::generate-salt[]
	@Test
	void generateSalt() {
		String salt = KeyGenerators.string().generateKey(); // generates a random 8-byte salt that is then hex-encoded
		assertThat(salt).isNotEmpty();
	}
	// end::generate-salt[]

	// tag::aes-cbc-bytes-encryptor[]
	@Test
	void aesCbcBytesEncryptor() {
		String salt = KeyGenerators.string().generateKey();
		AesCbcBytesEncryptor.withPassword("password", salt).build();
	}
	// end::aes-cbc-bytes-encryptor[]

}
