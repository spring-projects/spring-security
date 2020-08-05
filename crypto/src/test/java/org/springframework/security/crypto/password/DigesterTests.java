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
package org.springframework.security.crypto.password;

import org.junit.Test;

import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.codec.Utf8;

import static org.assertj.core.api.Assertions.assertThat;

public class DigesterTests {

	@Test
	public void digestIsCorrectFor3Iterations() {
		Digester digester = new Digester("SHA-1", 3);
		byte[] result = digester.digest(Utf8.encode("text"));
		// echo -n text | openssl sha1 -binary | openssl sha1 -binary | openssl sha1
		assertThat(new String(Hex.encode(result))).isEqualTo("3cfa28da425eca5b894f0af2b158adf7001e000f");
	}

}
