/*
 * Copyright 2002-2020 the original author or authors.
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
 * A CSRF token that is used to protect against CSRF attacks.<br/>
 * <br/>
 * This token provide protection from BREACH exploit by always returning a Base64Url encoded
 * random string (XOR-ed token value with salt) {@link #getToken()}. In order to check if an
 * instance token matches with the string value use
 * {@link #matches(String)}
 *
 * @author Ruby Hartono
 * @since 5.4
 */
@SuppressWarnings("serial")
public final class XorCsrfToken implements CsrfToken {

	/**
	 * Convenient method to provide generate token
	 *
	 * @return GenerateTokenProvider that generate XorCsrfToken with
	 *         {@link java.security.SecureRandom} empty constructor
	 * @see CookieCsrfTokenRepository
	 * @see HttpSessionCsrfTokenRepository
	 */
	public static GenerateTokenProvider<XorCsrfToken> createGenerateTokenProvider() {
		return (headerName, parameterName, value) -> new XorCsrfToken(headerName, parameterName, value);
	}

	/**
	 * Convenient method to provide generate token
	 *
	 * @param secureRandom instance to be set for the XorCsrfToken
	 * @return GenerateTokenProvider that that generate XorCsrfToken with
	 *         {@link java.security.SecureRandom} from parameter
	 * @see CookieCsrfTokenRepository
	 * @see HttpSessionCsrfTokenRepository
	 */
	public static GenerateTokenProvider<XorCsrfToken> createGenerateTokenProvider(SecureRandom secureRandom) {
		return (headerName, parameterName, value) -> new XorCsrfToken(headerName, parameterName, value, secureRandom);
	}

	private final byte[] tokenBytes;

	private final String parameterName;

	private final String headerName;

	private final SecureRandom secureRandom;

	/**
	 * Creates a new instance
	 *
	 * @param headerName    the HTTP header name to use
	 * @param parameterName the HTTP parameter name to use
	 * @param token         the value of the token (i.e. expected value of the HTTP
	 *                      parameter of parametername).
	 */
	public XorCsrfToken(String headerName, String parameterName, String token) {
		this(headerName, parameterName, token, new SecureRandom());
	}

	/**
	 * Creates a new instance
	 *
	 * @param headerName    the HTTP header name to use
	 * @param parameterName the HTTP parameter name to use
	 * @param token         the value of the token (i.e. expected value of the HTTP
	 *                      parameter of parametername).
	 * @param secureRandom  secure random instance to be used for random salt
	 */
	public XorCsrfToken(String headerName, String parameterName, String token, SecureRandom secureRandom) {
		Assert.hasLength(headerName, "headerName cannot be null or empty");
		Assert.hasLength(parameterName, "parameterName cannot be null or empty");
		Assert.hasLength(token, "token cannot be null or empty");
		this.headerName = headerName;
		this.parameterName = parameterName;
		this.tokenBytes = Utf8.encode(token);
		this.secureRandom = secureRandom;
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.security.web.csrf.CsrfToken#getHeaderName()
	 */
	public String getHeaderName() {
		return this.headerName;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.security.web.csrf.CsrfToken#getParameterName()
	 */
	public String getParameterName() {
		return this.parameterName;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.security.web.csrf.CsrfToken#getToken()
	 */
	public String getToken() {
		byte[] randomBytes = new byte[this.tokenBytes.length];
		this.secureRandom.nextBytes(randomBytes);

		byte[] xoredCsrf = xorCsrf(randomBytes, this.tokenBytes);

		byte[] combinedBytes = new byte[randomBytes.length + xoredCsrf.length];
		System.arraycopy(randomBytes, 0, combinedBytes, 0, randomBytes.length);
		System.arraycopy(xoredCsrf, 0, combinedBytes, randomBytes.length, xoredCsrf.length);

		// returning randomBytes + XOR csrf token
		return Base64.getUrlEncoder().encodeToString(combinedBytes);
	}

	public String getTokenValue() {
		return Utf8.decode(this.tokenBytes);
	}


	private static byte[] xorCsrf(byte[] randomBytes, byte[] csrfBytes) {
		byte[] xoredCsrf = new byte[csrfBytes.length];
		System.arraycopy(csrfBytes, 0, xoredCsrf, 0, csrfBytes.length);
		for (byte b : randomBytes) {
			for (int i = 0; i < xoredCsrf.length; i++) {
				xoredCsrf[i] ^= b;
			}
		}

		return xoredCsrf;
	}

	@Override
	public boolean matches(String token) {
		byte[] paramToken = null;

		try {
			paramToken = Base64.getUrlDecoder().decode(token);
		} catch (Exception ex) {
			return false;
		}

		int tokenSize = this.tokenBytes.length;

		if (paramToken.length == tokenSize) {
			return MessageDigest.isEqual(this.tokenBytes, paramToken);
		} else if (paramToken.length < tokenSize) {
			return false;
		}

		// extract token and random bytes
		int paramXorTokenOffset = paramToken.length - tokenSize;
		byte[] paramXoredToken = new byte[tokenSize];
		byte[] paramRandomBytes = new byte[paramXorTokenOffset];

		System.arraycopy(paramToken, 0, paramRandomBytes, 0, paramXorTokenOffset);
		System.arraycopy(paramToken, paramXorTokenOffset, paramXoredToken, 0, paramXoredToken.length);

		byte[] paramActualCsrfToken = xorCsrf(paramRandomBytes, paramXoredToken);

		// comparing this token with the actual csrf token from param
		return MessageDigest.isEqual(this.tokenBytes, paramActualCsrfToken);
	}
}
