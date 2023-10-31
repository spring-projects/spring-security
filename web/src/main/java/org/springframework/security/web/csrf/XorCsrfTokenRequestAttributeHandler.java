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
import java.util.function.Supplier;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.crypto.codec.Utf8;
import org.springframework.util.Assert;

/**
 * An implementation of the {@link CsrfTokenRequestHandler} interface that is capable of
 * masking the value of the {@link CsrfToken} on each request and resolving the raw token
 * value from the masked value as either a header or parameter value of the request.
 *
 * @author Steve Riesenberg
 * @since 5.8
 */
public final class XorCsrfTokenRequestAttributeHandler extends CsrfTokenRequestAttributeHandler {

	private SecureRandom secureRandom = new SecureRandom();

	/**
	 * Specifies the {@code SecureRandom} used to generate random bytes that are used to
	 * mask the value of the {@link CsrfToken} on each request.
	 * @param secureRandom the {@code SecureRandom} to use to generate random bytes
	 */
	public void setSecureRandom(SecureRandom secureRandom) {
		Assert.notNull(secureRandom, "secureRandom cannot be null");
		this.secureRandom = secureRandom;
	}

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			Supplier<CsrfToken> deferredCsrfToken) {
		Assert.notNull(request, "request cannot be null");
		Assert.notNull(response, "response cannot be null");
		Assert.notNull(deferredCsrfToken, "deferredCsrfToken cannot be null");
		Supplier<CsrfToken> updatedCsrfToken = deferCsrfTokenUpdate(deferredCsrfToken);
		super.handle(request, response, updatedCsrfToken);
	}

	private Supplier<CsrfToken> deferCsrfTokenUpdate(Supplier<CsrfToken> csrfTokenSupplier) {
		return new CachedCsrfTokenSupplier(() -> {
			CsrfToken csrfToken = csrfTokenSupplier.get();
			Assert.state(csrfToken != null, "csrfToken supplier returned null");
			String updatedToken = createXoredCsrfToken(this.secureRandom, csrfToken.getToken());
			return new DefaultCsrfToken(csrfToken.getHeaderName(), csrfToken.getParameterName(), updatedToken);
		});
	}

	@Override
	public String resolveCsrfTokenValue(HttpServletRequest request, CsrfToken csrfToken) {
		String actualToken = super.resolveCsrfTokenValue(request, csrfToken);
		return getTokenValue(actualToken, csrfToken.getToken());
	}

	private static String getTokenValue(String actualToken, String token) {
		byte[] actualBytes;
		try {
			actualBytes = Base64.getUrlDecoder().decode(actualToken);
		}
		catch (Exception ex) {
			return null;
		}

		byte[] tokenBytes = Utf8.encode(token);
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

	private static String createXoredCsrfToken(SecureRandom secureRandom, String token) {
		byte[] tokenBytes = Utf8.encode(token);
		byte[] randomBytes = new byte[tokenBytes.length];
		secureRandom.nextBytes(randomBytes);

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

	private static final class CachedCsrfTokenSupplier implements Supplier<CsrfToken> {

		private final Supplier<CsrfToken> delegate;

		private CsrfToken csrfToken;

		private CachedCsrfTokenSupplier(Supplier<CsrfToken> delegate) {
			this.delegate = delegate;
		}

		@Override
		public CsrfToken get() {
			if (this.csrfToken == null) {
				this.csrfToken = this.delegate.get();
			}
			return this.csrfToken;
		}

	}

}
