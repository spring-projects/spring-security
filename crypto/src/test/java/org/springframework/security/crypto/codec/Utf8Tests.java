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
package org.springframework.security.crypto.codec;

import static org.assertj.core.api.Assertions.*;

import org.junit.*;

import java.util.*;

/**
 * @author Luke Taylor
 */
public class Utf8Tests {

	// SEC-1752
	@Test
	public void utf8EncodesAndDecodesCorrectly() throws Exception {
		byte[] bytes = Utf8.encode("6048b75ed560785c");
		assertThat(bytes).hasSize(16);
		assertThat(Arrays.equals("6048b75ed560785c".getBytes("UTF-8"), bytes)).isTrue();

		String decoded = Utf8.decode(bytes);

		assertThat(decoded).isEqualTo("6048b75ed560785c");
	}
}
