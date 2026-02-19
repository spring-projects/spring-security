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

package org.springframework.security.web.csrf;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Tests for {@link XorCsrfTokenEncoder}.
 *
 * @author Cheol Jeon
 * @since
 */
public class XorCsrfTokenEncoderTest {

	private XorCsrfTokenEncoder encoder;

	private CsrfToken csrfToken;

	@BeforeEach
	void setup() {
		this.encoder = new XorCsrfTokenEncoder();
		this.csrfToken = new CookieCsrfTokenRepository().generateToken(new MockHttpServletRequest());
	}

	@Test
	void encodeAndDecode_shouldReturnOriginalToken() {
		String originalToken = csrfToken.getToken();

		String encoded = encoder.encode(originalToken);
		assertNotNull(encoded, "Encoded token should not be null");

		String decoded = encoder.decode(encoded, originalToken);
		assertEquals(originalToken, decoded, "Decoded token should match the original");
	}

	@Test
	void decode_withInvalidBase64_shouldReturnNull() {
		String invalidEncoded = "not-base64!!";

		String decoded = encoder.decode(invalidEncoded, "any-token");
		assertNull(decoded, "Decoding invalid base64 should return null");
	}

	@Test
	void decode_withIncorrectLength_shouldReturnNull() {
		String originalToken = csrfToken.getToken();

		String encoded = encoder.encode(originalToken);

		// The CSRF token generated in Spring Security uses UUID.randomUUID().toString(),
		// which produces a 36‑byte ASCII string (hyphens + hex digits). Because 36 is
		// a multiple of 3, Base64 encoding of that input will not include padding ('=').
		// Therefore, removing a single character from the encoded string (encoded.length() - 1)
		// is sufficient here to simulate corruption of the token for this test case —
		// i.e. it will produce an encoded value that no longer decodes back to the original token.
		String truncated = encoded.substring(0, encoded.length() - 1);

		String decoded = encoder.decode(truncated, originalToken);
		assertNull(decoded, "Decoding token with invalid length should return null");
	}

	@Test
	void encode_shouldProduceDifferentValuesForSameInput() {
		String originalToken = csrfToken.getToken();

		String encoded1 = encoder.encode(originalToken);
		String encoded2 = encoder.encode(originalToken);

		// Because random bytes used, encoded results should differ
		assertNotEquals(encoded1, encoded2, "Encoded values for same input should differ");
	}
}
