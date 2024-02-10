/*
 * Copyright 2013-2024 the original author or authors.
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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;

import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Dave Syer
 *
 */
@DisabledOnOs(OS.WINDOWS)
public class KeyStoreKeyFactoryTests {

	@Test
	public void initializeEncryptorFromKeyStore() {
		char[] password = "foobar".toCharArray();
		KeyStoreKeyFactory factory = new KeyStoreKeyFactory(new ClassPathResource("keystore.jks"), password);
		RsaSecretEncryptor encryptor = new RsaSecretEncryptor(factory.getKeyPair("test"));
		assertThat(encryptor.canDecrypt()).as("Should be able to decrypt").isTrue();
		assertThat(encryptor.decrypt(encryptor.encrypt("foo"))).isEqualTo("foo");
	}

	@Test
	public void initializeEncryptorFromPkcs12KeyStore() {
		char[] password = "letmein".toCharArray();
		KeyStoreKeyFactory factory = new KeyStoreKeyFactory(new ClassPathResource("keystore.pkcs12"), password);
		RsaSecretEncryptor encryptor = new RsaSecretEncryptor(factory.getKeyPair("mytestkey"));
		assertThat(encryptor.canDecrypt()).as("Should be able to decrypt").isTrue();
		assertThat(encryptor.decrypt(encryptor.encrypt("foo"))).isEqualTo("foo");
	}

	@Test
	public void initializeEncryptorFromTrustedCertificateInKeyStore() {
		char[] password = "foobar".toCharArray();
		KeyStoreKeyFactory factory = new KeyStoreKeyFactory(new ClassPathResource("keystore.jks"), password);
		RsaSecretEncryptor encryptor = new RsaSecretEncryptor(factory.getKeyPair("testcertificate"));
		assertThat(encryptor.canDecrypt()).as("Should not be able to decrypt").isFalse();
		assertThat(encryptor.encrypt("foo")).isNotEqualTo("foo");
	}

	@Test
	public void initializeEncryptorFromTrustedCertificateInPkcs12KeyStore() {
		char[] password = "letmein".toCharArray();
		KeyStoreKeyFactory factory = new KeyStoreKeyFactory(new ClassPathResource("keystore.pkcs12"), password);
		RsaSecretEncryptor encryptor = new RsaSecretEncryptor(factory.getKeyPair("mytestcertificate"));
		assertThat(encryptor.canDecrypt()).as("Should not be able to decrypt").isFalse();
		assertThat(encryptor.encrypt("foo")).isNotEqualTo("foo");
	}

}
