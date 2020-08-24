/*
 * Copyright 2002-2016 the original author or authors.
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

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class EncryptorsTests {

	@Test
	public void stronger() throws Exception {
		CryptoAssumptions.assumeGCMJCE();
		BytesEncryptor encryptor = Encryptors.stronger("password", "5c0744940b5c369b");
		byte[] result = encryptor.encrypt("text".getBytes("UTF-8"));
		assertThat(result).isNotNull();
		assertThat(new String(result).equals("text")).isFalse();
		assertThat(new String(encryptor.decrypt(result))).isEqualTo("text");
		assertThat(new String(result)).isNotEqualTo(new String(encryptor.encrypt("text".getBytes())));
	}

	@Test
	public void standard() throws Exception {
		CryptoAssumptions.assumeCBCJCE();
		BytesEncryptor encryptor = Encryptors.standard("password", "5c0744940b5c369b");
		byte[] result = encryptor.encrypt("text".getBytes("UTF-8"));
		assertThat(result).isNotNull();
		assertThat(new String(result).equals("text")).isFalse();
		assertThat(new String(encryptor.decrypt(result))).isEqualTo("text");
		assertThat(new String(result)).isNotEqualTo(new String(encryptor.encrypt("text".getBytes())));
	}

	@Test
	public void preferred() {
		CryptoAssumptions.assumeGCMJCE();
		TextEncryptor encryptor = Encryptors.delux("password", "5c0744940b5c369b");
		String result = encryptor.encrypt("text");
		assertThat(result).isNotNull();
		assertThat(result.equals("text")).isFalse();
		assertThat(encryptor.decrypt(result)).isEqualTo("text");
		assertThat(result.equals(encryptor.encrypt("text"))).isFalse();
	}

	@Test
	public void text() {
		CryptoAssumptions.assumeCBCJCE();
		TextEncryptor encryptor = Encryptors.text("password", "5c0744940b5c369b");
		String result = encryptor.encrypt("text");
		assertThat(result).isNotNull();
		assertThat(result.equals("text")).isFalse();
		assertThat(encryptor.decrypt(result)).isEqualTo("text");
		assertThat(result.equals(encryptor.encrypt("text"))).isFalse();
	}

	@Test
	public void queryableText() {
		CryptoAssumptions.assumeCBCJCE();
		TextEncryptor encryptor = Encryptors.queryableText("password", "5c0744940b5c369b");
		String result = encryptor.encrypt("text");
		assertThat(result).isNotNull();
		assertThat(result.equals("text")).isFalse();
		assertThat(encryptor.decrypt(result)).isEqualTo("text");
		assertThat(result.equals(encryptor.encrypt("text"))).isTrue();
	}

	@Test
	public void noOpText() {
		TextEncryptor encryptor = Encryptors.noOpText();
		assertThat(encryptor.encrypt("text")).isEqualTo("text");
		assertThat(encryptor.decrypt("text")).isEqualTo("text");
	}

}
