/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.crypto.keygen;

import static org.assertj.core.api.Assertions.*;

import java.util.Arrays;

import org.junit.Test;
import org.springframework.security.crypto.codec.Hex;

public class KeyGeneratorsTests {

	@Test
	public void secureRandom() {
		BytesKeyGenerator keyGenerator = KeyGenerators.secureRandom();
		assertThat(keyGenerator.getKeyLength()).isEqualTo(8);
		byte[] key = keyGenerator.generateKey();
		assertThat(key).hasSize(8);
		byte[] key2 = keyGenerator.generateKey();
		assertThat(Arrays.equals(key, key2)).isFalse();
	}

	@Test
	public void secureRandomCustomLength() {
		BytesKeyGenerator keyGenerator = KeyGenerators.secureRandom(21);
		assertThat(keyGenerator.getKeyLength()).isEqualTo(21);
		byte[] key = keyGenerator.generateKey();
		assertThat(key).hasSize(21);
		byte[] key2 = keyGenerator.generateKey();
		assertThat(Arrays.equals(key, key2)).isFalse();
	}

	@Test
	public void shared() {
		BytesKeyGenerator keyGenerator = KeyGenerators.shared(21);
		assertThat(keyGenerator.getKeyLength()).isEqualTo(21);
		byte[] key = keyGenerator.generateKey();
		assertThat(key).hasSize(21);
		byte[] key2 = keyGenerator.generateKey();
		assertThat(Arrays.equals(key, key2)).isTrue();
	}

	@Test
	public void string() {
		StringKeyGenerator keyGenerator = KeyGenerators.string();
		String hexStringKey = keyGenerator.generateKey();
		assertThat(hexStringKey.length()).isEqualTo(16);
		assertThat(Hex.decode(hexStringKey)).hasSize(8);
		String hexStringKey2 = keyGenerator.generateKey();
		assertThat(hexStringKey.equals(hexStringKey2)).isFalse();
	}

}
