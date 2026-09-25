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

import org.jspecify.annotations.Nullable;
import org.springframework.core.log.LogMessage;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.util.Assert;

import java.security.SecureRandom;
import java.util.Base64;

import static org.springframework.security.web.csrf.CsrfTokenRequestHandlerLoggerHolder.logger;

/**
 * Implementation of CsrfTokenEncoder that uses XOR operation combined with a random key
 * to encode and decode CSRF tokens.
 *
 * The encode method generates a random byte array and XORs it with the UTF-8 bytes of the token,
 * then combines both arrays and encodes them in Base64 URL-safe format.
 *
 * The decode method reverses this process by decoding the Base64 string, splitting the bytes,
 * and XORing the two parts to retrieve the original token.
 *
 * This approach enhances CSRF token security by obfuscating the token value with randomness.
 *
 * @author Cheol Jeon
 * @since
 * @see XorCsrfTokenRequestAttributeHandler
 */
public class XorCsrfTokenEncoder implements CsrfTokenEncoder {
	private SecureRandom secureRandom;

	public XorCsrfTokenEncoder() {
		this(new SecureRandom());
	}

	public XorCsrfTokenEncoder(SecureRandom secureRandom) {
		Assert.notNull(secureRandom, "secureRandom cannot be null");
		this.secureRandom = secureRandom;
	}

	@Override
	public String encode(String token) {
		byte[] tokenBytes = Utf8.encode(token);
		byte[] randomBytes = new byte[tokenBytes.length];
		secureRandom.nextBytes(randomBytes);

		byte[] xoredBytes = xor(randomBytes, tokenBytes);
		byte[] combinedBytes = new byte[tokenBytes.length + randomBytes.length];
		System.arraycopy(randomBytes, 0, combinedBytes, 0, randomBytes.length);
		System.arraycopy(xoredBytes, 0, combinedBytes, randomBytes.length, xoredBytes.length);

		return Base64.getUrlEncoder().encodeToString(combinedBytes);
	}

	@Override
	public @Nullable String decode(String encodedToken, String originalToken) {
		byte[] actualBytes;
		try {
			actualBytes = Base64.getUrlDecoder().decode(encodedToken);
		}
		catch (Exception ex) {
			logger.trace(LogMessage.format("Not returning the CSRF token since it's not Base64-encoded"), ex);
			return null;
		}

		byte[] tokenBytes = Utf8.encode(originalToken);
		int tokenSize = tokenBytes.length;
		if (actualBytes.length != tokenSize * 2) {
			logger.trace(LogMessage.format(
					"Not returning the CSRF token since its Base64-decoded length (%d) is not equal to (%d)",
					actualBytes.length, tokenSize * 2));
			return null;
		}

		// extract token and random bytes
		byte[] xoredCsrf = new byte[tokenSize];
		byte[] randomBytes = new byte[tokenSize];

		System.arraycopy(actualBytes, 0, randomBytes, 0, tokenSize);
		System.arraycopy(actualBytes, tokenSize, xoredCsrf, 0, tokenSize);

		byte[] csrfBytes = xor(randomBytes, xoredCsrf);
		return Utf8.decode(csrfBytes);
	}

	private byte[] xor(byte[] randomBytes, byte[] csrfBytes) {
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
