/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.messaging.web.csrf;

import java.util.Base64;

import org.springframework.security.crypto.codec.Utf8;
import org.springframework.util.Assert;

/**
 * Copied from
 * {@link org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler}.
 *
 * @see <a href=
 * "https://github.com/spring-projects/spring-security/issues/12378">gh-12378</a>
 */
final class XorCsrfTokenUtils {

	private XorCsrfTokenUtils() {
	}

	static String getTokenValue(String actualToken, String token) {
		byte[] actualBytes;
		try {
			actualBytes = Base64.getUrlDecoder().decode(actualToken);
		}
		catch (Exception ex) {
			return null;
		}

		byte[] tokenBytes = Utf8.encode(token);
		int tokenSize = tokenBytes.length;
		if (actualBytes.length != tokenSize * 2) {
			return null;
		}

		// extract token and random bytes
		byte[] xoredCsrf = new byte[tokenSize];
		byte[] randomBytes = new byte[tokenSize];

		System.arraycopy(actualBytes, 0, randomBytes, 0, tokenSize);
		System.arraycopy(actualBytes, tokenSize, xoredCsrf, 0, tokenSize);

		byte[] csrfBytes = xorCsrf(randomBytes, xoredCsrf);
		return Utf8.decode(csrfBytes);
	}

	private static byte[] xorCsrf(byte[] randomBytes, byte[] csrfBytes) {
		Assert.isTrue(randomBytes.length == csrfBytes.length, "arrays must be equal length");
		int len = csrfBytes.length;
		byte[] xoredCsrf = new byte[len];
		System.arraycopy(csrfBytes, 0, xoredCsrf, 0, len);
		for (int i = 0; i < len; i++) {
			xoredCsrf[i] ^= randomBytes[i];
		}
		return xoredCsrf;
	}

}
