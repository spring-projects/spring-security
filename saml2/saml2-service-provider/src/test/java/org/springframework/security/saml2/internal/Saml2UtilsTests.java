/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.saml2.internal;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import org.springframework.security.saml2.Saml2Exception;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class Saml2UtilsTests {

	@Test
	void testSaml2InflateWhenLargePayloadThenErrors() {
		byte[] b = new byte[1024 * 1024 + 1];
		for (int i = 0; i < b.length; i++) {
			b[i] = 56;
		}
		byte[] deflated = Saml2Utils.samlDeflate(new String(b, StandardCharsets.UTF_8));
		assertThatExceptionOfType(Saml2Exception.class).isThrownBy(() -> Saml2Utils.samlInflate(deflated))
			.withStackTraceContaining("SAML payload exceeded maximum size");
	}

}
