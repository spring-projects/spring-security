/*
 * Copyright 2011-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.crypto.codec;

import org.junit.Test;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

public class CodecsTests {

	public static final String SOURCE = "Hi!";
	public static final String BASE64_STRING = "SGkh";
	public static final String HEXA_STRING = "486921";
	public static final byte[] BYTE_ARRAY = {0x1, 0x2, 0x3};

	@Test
	public void shouldSatisfyCodecContract() throws Exception {
		Codec codec = Codecs.base64();
		assertThat(Arrays.equals(codec.decode(codec.encode(BYTE_ARRAY)), BYTE_ARRAY))
			.isTrue();
		assertThat(BASE64_STRING.equals(codec.encode(codec.decode(BASE64_STRING))))
			.isTrue();

		codec = Codecs.hexadecimal();
		assertThat(Arrays.equals(codec.decode(codec.encode(BYTE_ARRAY)), BYTE_ARRAY))
			.isTrue();
		assertThat(HEXA_STRING.equals(codec.encode(codec.decode(HEXA_STRING))))
			.isTrue();
	}

	@Test
	public void shouldEncodeInBase64() throws Exception {
		assertThat(Codecs.base64().encode(SOURCE.getBytes()))
			.isEqualToIgnoringCase(BASE64_STRING);
	}

	@Test
	public void shouldDecodeBase64() throws Exception {
		assertThat(Codecs.base64().decode(BASE64_STRING))
			.isEqualTo(SOURCE.getBytes());
	}

	@Test
	public void shouldEncodeInHexadecimal() throws Exception {
		assertThat(Codecs.hexadecimal().encode(SOURCE.getBytes()))
			.isEqualToIgnoringCase(HEXA_STRING);
	}

	@Test
	public void shouldDecodeHexadecimal() throws Exception {
		assertThat(Codecs.hexadecimal().decode(HEXA_STRING))
			.isEqualTo(SOURCE.getBytes());
	}
}
