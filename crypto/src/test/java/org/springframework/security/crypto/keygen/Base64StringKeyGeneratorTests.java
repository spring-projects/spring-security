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

import org.junit.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.*;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class Base64StringKeyGeneratorTests {

	@Test(expected = IllegalArgumentException.class)
	public void constructorIntWhenLessThan32ThenIllegalArgumentException() {
		new Base64StringKeyGenerator(31);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorEncoderWhenEncoderNullThenThrowsIllegalArgumentException() {
		Base64.Encoder encoder = null;
		new Base64StringKeyGenerator(null);
	}

	@Test
	public void generateKeyWhenDefaultConstructorThen32Bytes() {
		String result = new Base64StringKeyGenerator().generateKey();
		assertThat(Base64.getDecoder().decode(result.getBytes())).hasSize(32);
	}

	@Test
	public void generateKeyWhenCustomKeySizeThen32Bytes() {
		int size = 40;
		String result = new Base64StringKeyGenerator(size).generateKey();
		assertThat(Base64.getDecoder().decode(result.getBytes())).hasSize(size);
	}

	@Test
	public void generateKeyWhenBase64Then32Bytes() {
		String result = new Base64StringKeyGenerator(Base64.getUrlEncoder()).generateKey();
		assertThat(Base64.getUrlDecoder().decode(result.getBytes())).hasSize(32);
	}

	@Test
	public void generateKeyWhenBase64AndCustomKeySizeThen32Bytes() {
		int size = 40;
		String result = new Base64StringKeyGenerator(Base64.getUrlEncoder(), size).generateKey();
		assertThat(Base64.getUrlDecoder().decode(result.getBytes())).hasSize(size);
	}

}
