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
package org.springframework.security.crypto.util;

import java.util.Arrays;

import org.junit.Test;

import org.springframework.security.crypto.codec.Hex;

import static org.assertj.core.api.Assertions.assertThat;

public class EncodingUtilsTests {

	@Test
	public void hexEncode() {
		byte[] bytes = new byte[] { (byte) 0x01, (byte) 0xFF, (byte) 65, (byte) 66, (byte) 67, (byte) 0xC0, (byte) 0xC1,
				(byte) 0xC2 };
		String result = new String(Hex.encode(bytes));
		assertThat(result).isEqualTo("01ff414243c0c1c2");
	}

	@Test
	public void hexDecode() {
		byte[] bytes = new byte[] { (byte) 0x01, (byte) 0xFF, (byte) 65, (byte) 66, (byte) 67, (byte) 0xC0, (byte) 0xC1,
				(byte) 0xC2 };
		byte[] result = Hex.decode("01ff414243c0c1c2");
		assertThat(Arrays.equals(bytes, result)).isTrue();
	}

	@Test
	public void concatenate() {
		byte[] bytes = new byte[] { (byte) 0x01, (byte) 0xFF, (byte) 65, (byte) 66, (byte) 67, (byte) 0xC0, (byte) 0xC1,
				(byte) 0xC2 };
		byte[] one = new byte[] { (byte) 0x01 };
		byte[] two = new byte[] { (byte) 0xFF, (byte) 65, (byte) 66 };
		byte[] three = new byte[] { (byte) 67, (byte) 0xC0, (byte) 0xC1, (byte) 0xC2 };
		assertThat(Arrays.equals(bytes, EncodingUtils.concatenate(one, two, three))).isTrue();
	}

	@Test
	public void subArray() {
		byte[] bytes = new byte[] { (byte) 0x01, (byte) 0xFF, (byte) 65, (byte) 66, (byte) 67, (byte) 0xC0, (byte) 0xC1,
				(byte) 0xC2 };
		byte[] two = new byte[] { (byte) 0xFF, (byte) 65, (byte) 66 };
		byte[] subArray = EncodingUtils.subArray(bytes, 1, 4);
		assertThat(subArray).hasSize(3);
		assertThat(Arrays.equals(two, subArray)).isTrue();
	}

}
