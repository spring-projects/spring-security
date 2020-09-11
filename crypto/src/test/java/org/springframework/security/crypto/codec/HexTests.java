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

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Test cases for {@link Hex}.
 *
 * @author Kazuki Shimizu
 */
public class HexTests {

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
		assertThatIllegalArgumentException().isThrownBy(() -> Hex.decode("414243444"))
				.withMessage("Hex-encoded string must have an even number of characters");
	}

	@Test
	public void decodeExistNonHexCharAtFirst() {
		assertThatIllegalArgumentException().isThrownBy(() -> Hex.decode("G0"))
				.withMessage("Detected a Non-hex character at 1 or 2 position");
	}

	@Test
	public void decodeExistNonHexCharAtSecond() {
		assertThatIllegalArgumentException().isThrownBy(() -> Hex.decode("410G"))
				.withMessage("Detected a Non-hex character at 3 or 4 position");
	}

	@Test
	public void decodeExistNonHexCharAtBoth() {
		assertThatIllegalArgumentException().isThrownBy(() -> Hex.decode("4142GG"))
				.withMessage("Detected a Non-hex character at 5 or 6 position");
	}

}
