/*
 * Copyright 2002-2022 the original author or authors.
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

import java.security.SecureRandom;
import java.util.Base64;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.crypto.codec.Utf8;

/**
 * @author Steve Riesenberg
 */
public final class XorCsrfTokenRequestHandler implements CsrfTokenRequestAttributeHandler, CsrfTokenRequestResolver {

	private final DefaultCsrfTokenRequestHandler delegate = new DefaultCsrfTokenRequestHandler();

	private SecureRandom secureRandom = new SecureRandom();

	/**
	 * TODO
	 *
	 * @param secureRandom
	 */
	public void setSecureRandom(SecureRandom secureRandom) {
		this.secureRandom = secureRandom;
	}

	/**
	 * The {@link CsrfToken} is available as a request attribute named
	 * {@code CsrfToken.class.getName()}. By default, an additional request attribute that
	 * is the same as {@link CsrfToken#getParameterName()} is set. This attribute allows
	 * overriding the additional attribute.
	 * @param csrfRequestAttributeName the name of an additional request attribute with
	 * the value of the CsrfToken. Default is {@link CsrfToken#getParameterName()}
	 */
	public void setCsrfRequestAttributeName(String csrfRequestAttributeName) {
		this.delegate.setCsrfRequestAttributeName(csrfRequestAttributeName);
	}

	@Override
	public void handle(HttpServletRequest request, CsrfToken csrfToken) {
		String updatedToken = createXoredCsrfToken(csrfToken.getToken());
		DefaultCsrfToken updatedCsrfToken = new DefaultCsrfToken(csrfToken.getHeaderName(),
				csrfToken.getParameterName(), updatedToken);
		this.delegate.handle(request, updatedCsrfToken);
	}

	@Override
	public String resolve(HttpServletRequest request, CsrfToken csrfToken) {
		String actualToken = this.delegate.resolve(request, csrfToken);
		byte[] actualBytes;
		try {
			actualBytes = Base64.getUrlDecoder().decode(actualToken);
		}
		catch (Exception ex) {
			return null;
		}

		byte[] tokenBytes = Utf8.encode(csrfToken.getToken());
		int tokenSize = tokenBytes.length;
		if (actualBytes.length < tokenSize) {
			return null;
		}

		// extract token and random bytes
		int randomBytesSize = actualBytes.length - tokenSize;
		byte[] xoredCsrf = new byte[tokenSize];
		byte[] randomBytes = new byte[randomBytesSize];

		System.arraycopy(actualBytes, 0, randomBytes, 0, randomBytesSize);
		System.arraycopy(actualBytes, randomBytesSize, xoredCsrf, 0, tokenSize);

		byte[] csrfBytes = xorCsrf(randomBytes, xoredCsrf);
		return Utf8.decode(csrfBytes);
	}

	private String createXoredCsrfToken(String token) {
		byte[] tokenBytes = Utf8.encode(token);
		byte[] randomBytes = new byte[tokenBytes.length];
		this.secureRandom.nextBytes(randomBytes);

		byte[] xoredBytes = xorCsrf(randomBytes, tokenBytes);
		byte[] combinedBytes = new byte[tokenBytes.length + randomBytes.length];
		System.arraycopy(randomBytes, 0, combinedBytes, 0, randomBytes.length);
		System.arraycopy(xoredBytes, 0, combinedBytes, randomBytes.length, xoredBytes.length);

		return Base64.getUrlEncoder().encodeToString(combinedBytes);
	}

	private static byte[] xorCsrf(byte[] randomBytes, byte[] csrfBytes) {
		int len = Math.min(randomBytes.length, csrfBytes.length);
		byte[] xoredCsrf = new byte[len];
		System.arraycopy(csrfBytes, 0, xoredCsrf, 0, csrfBytes.length);
		for (int i = 0; i < len; i++) {
			xoredCsrf[i] ^= randomBytes[i];
		}
		return xoredCsrf;
	}

}
