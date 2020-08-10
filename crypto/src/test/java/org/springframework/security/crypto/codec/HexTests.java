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
package org.springframework.security.crypto.codec;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test cases for {@link Hex}.
 *
 * @author Kazuki Shimizu
 */
public class HexTests {

	@Rule
	public ExpectedException expectedException = ExpectedException.none();

	@Test
	public void encode() {
		assertThat(Hex.encode(new byte[] { (byte) 'A', (byte) 'B', (byte) 'C', (byte) 'D' }))
				.isEqualTo(new char[] { '4', '1', '4', '2', '4', '3', '4', '4' });
	}

	@Test
	public void encodeEmptyByteArray() {
		assertThat(Hex.encode(new byte[] {})).isEmpty();
	}

	@Test
	public void decode() {
		assertThat(Hex.decode("41424344")).isEqualTo(new byte[] { (byte) 'A', (byte) 'B', (byte) 'C', (byte) 'D' });
	}

	@Test
	public void decodeEmptyString() {
		assertThat(Hex.decode("")).isEmpty();
	}

	@Test
	public void decodeNotEven() {
		expectedException.expect(IllegalArgumentException.class);
		expectedException.expectMessage("Hex-encoded string must have an even number of characters");
		Hex.decode("414243444");
	}

	@Test
	public void decodeExistNonHexCharAtFirst() {
		expectedException.expect(IllegalArgumentException.class);
		expectedException.expectMessage("Detected a Non-hex character at 1 or 2 position");
		Hex.decode("G0");
	}

	@Test
	public void decodeExistNonHexCharAtSecond() {
		expectedException.expect(IllegalArgumentException.class);
		expectedException.expectMessage("Detected a Non-hex character at 3 or 4 position");
		Hex.decode("410G");
	}

	@Test
	public void decodeExistNonHexCharAtBoth() {
		expectedException.expect(IllegalArgumentException.class);
		expectedException.expectMessage("Detected a Non-hex character at 5 or 6 position");
		Hex.decode("4142GG");
	}

}
