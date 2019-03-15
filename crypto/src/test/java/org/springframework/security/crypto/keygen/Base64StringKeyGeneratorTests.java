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

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;
import org.springframework.security.crypto.codec.Base64;

/**
 * @author Rob Winch
 * @since 4.2.6
 */
public class Base64StringKeyGeneratorTests {
	@Test(expected = IllegalArgumentException.class)
	public void constructorIntWhenLessThan32ThenIllegalArgumentException() {
		new Base64StringKeyGenerator(31);
	}

	@Test
	public void generateKeyWhenDefaultConstructorThen32Bytes() {
		String result = new Base64StringKeyGenerator().generateKey();
		assertThat(Base64.decode(result.getBytes())).hasSize(32);
	}

	@Test
	public void generateKeyWhenCustomKeySizeThen32Bytes() {
		int size = 40;
		String result = new Base64StringKeyGenerator(size).generateKey();
		assertThat(Base64.decode(result.getBytes())).hasSize(size);
	}
}
