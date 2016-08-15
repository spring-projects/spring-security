/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.csrf;

import org.springframework.security.crypto.codec.Base64;
import org.springframework.util.Assert;

import java.security.SecureRandom;

/**
 * A CSRF token that is used to protect against CSRF attacks.
 *
 * @author Rob Winch
 * @author John Ray
 * @since 3.2
 */
@SuppressWarnings("serial")
public final class DefaultCsrfToken implements CsrfToken {

	private static final int CSRF_VALUE_SIZE = 16;       // 128 bit CSRF value

	private static final SecureRandom secureRandom = new SecureRandom();

	private final String parameterName;

	private final String headerName;

	private final byte[] csrfToken;

	/**
	 * Creates a new instance
	 * @param headerName the HTTP header name to use
	 * @param parameterName the HTTP parameter name to use
	 */
	public DefaultCsrfToken(String headerName, String parameterName) {
		Assert.hasLength(headerName, "headerName cannot be null or empty");
		Assert.hasLength(parameterName, "parameterName cannot be null or empty");
		this.headerName = headerName;
		this.parameterName = parameterName;
		csrfToken = secureRandom.generateSeed(CSRF_VALUE_SIZE);
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.security.web.csrf.CsrfToken#getHeaderName()
	 */
	public String getHeaderName() {
		return headerName;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.security.web.csrf.CsrfToken#getParameterName()
	 */
	public String getParameterName() {
		return parameterName;
	}

	/**
	 * Get the CSRF token value. Each call to this method will return a unique
	 * value to defeat a possible BREACH attack.
	 *
	 * <p>The value consists of a 128 bit random mask followed by a 128 bit token
	 * XORed against the mask. The value is Base64 encoded.
	 *
	 * @return A unique CSRF token.
	 */
	public String getToken() {
		byte[] encodedToken = new byte[CSRF_VALUE_SIZE*2];

		byte[] mask = secureRandom.generateSeed(CSRF_VALUE_SIZE);
		for (int i=0; i < CSRF_VALUE_SIZE; i++) {
			encodedToken[i] = mask[i];
			encodedToken[i+CSRF_VALUE_SIZE] = (byte)(csrfToken[i] ^ mask[i]);
		}

		return new String(Base64.encode(encodedToken));
	}

	/*
     * (non-Javadoc)
     *
     * @see org.springframework.security.web.csrf.CsrfToken#isValid()
     */
	public boolean isValid(String value) {
		if ((value == null) || (value.length() == 0))
			return false;

		byte[] encodedToken;
		try {
			encodedToken = Base64.decode(value.getBytes());
		} catch (IllegalArgumentException e) {
			return false;
		}

		if (encodedToken.length != (CSRF_VALUE_SIZE*2))
			return false;

		for (int i=0; i < CSRF_VALUE_SIZE; i++)
			if (csrfToken[i] != (encodedToken[i] ^ encodedToken[i+CSRF_VALUE_SIZE]))
				return false;

		return true;
	}

}
