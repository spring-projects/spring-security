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

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

import org.springframework.security.crypto.codec.Utf8;
import org.springframework.util.Assert;

/**
 * A CSRF token that is used to protect against CSRF attacks.
 *
 * @author Rob Winch
 * @since 3.2
 */
@SuppressWarnings("serial")
public final class DefaultCsrfToken implements CsrfToken {

	private final String token;

	private final String parameterName;

	private final String headerName;

	private final transient SecureRandom secureRandom;

	/**
	 * Creates a new instance
	 * @param headerName the HTTP header name to use
	 * @param parameterName the HTTP parameter name to use
	 * @param token the value of the token (i.e. expected value of the HTTP parameter of
	 * parametername).
	 */
	public DefaultCsrfToken(String headerName, String parameterName, String token) {
		Assert.hasLength(headerName, "headerName cannot be null or empty");
		Assert.hasLength(parameterName, "parameterName cannot be null or empty");
		Assert.hasLength(token, "token cannot be null or empty");
		this.headerName = headerName;
		this.parameterName = parameterName;
		this.token = token;
		this.secureRandom = null;
	}

	/**
	 * Creates a new instance.
	 * @param headerName the HTTP header name to use
	 * @param parameterName the HTTP parameter name to use
	 * @param token the value of the token (i.e. expected value of the HTTP parameter of
	 * parametername).
	 * @param secureRandom The {@link SecureRandom} to use for generating salt values
	 */
	DefaultCsrfToken(String headerName, String parameterName, String token, SecureRandom secureRandom) {
		Assert.hasLength(headerName, "headerName cannot be null or empty");
		Assert.hasLength(parameterName, "parameterName cannot be null or empty");
		Assert.hasLength(token, "token cannot be null or empty");
		Assert.notNull(secureRandom, "secureRandom cannot be null");
		this.headerName = headerName;
		this.parameterName = parameterName;
		this.token = token;
		this.secureRandom = secureRandom;
	}

	@Override
	public String getHeaderName() {
		return this.headerName;
	}

	@Override
	public String getParameterName() {
		return this.parameterName;
	}

	@Override
	public String getToken() {
		return this.isXorRandomSecretEnabled() ? this.createXoredCsrfToken() : this.token;
	}

	@Override
	public boolean matches(String token) {
		if (!this.isXorRandomSecretEnabled()) {
			return CsrfToken.super.matches(token);
		}

		byte[] actualBytes;
		try {
			actualBytes = Base64.getUrlDecoder().decode(token);
		}
		catch (Exception ex) {
			return false;
		}

		byte[] tokenBytes = Utf8.encode(this.token);
		int tokenSize = tokenBytes.length;
		if (actualBytes.length < tokenSize) {
			return false;
		}

		// extract token and random bytes
		int randomBytesSize = actualBytes.length - tokenSize;
		byte[] xoredCsrf = new byte[tokenSize];
		byte[] randomBytes = new byte[randomBytesSize];

		System.arraycopy(actualBytes, 0, randomBytes, 0, randomBytesSize);
		System.arraycopy(actualBytes, randomBytesSize, xoredCsrf, 0, tokenSize);

		byte[] csrfBytes = xorCsrf(randomBytes, xoredCsrf);

		// comparing this token with the actual csrf token from param
		return MessageDigest.isEqual(tokenBytes, csrfBytes);
	}

	String getRawToken() {
		return this.token;
	}

	private boolean isXorRandomSecretEnabled() {
		return (this.secureRandom != null);
	}

	private String createXoredCsrfToken() {
		byte[] tokenBytes = Utf8.encode(this.token);
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
