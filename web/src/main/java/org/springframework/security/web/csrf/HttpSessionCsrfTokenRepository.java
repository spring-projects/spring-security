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
import java.util.UUID;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * A {@link CsrfTokenRepository} that stores the {@link CsrfToken} in the
 * {@link HttpSession}.
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class HttpSessionCsrfTokenRepository implements CsrfTokenRepository {

	private static final String DEFAULT_CSRF_PARAMETER_NAME = "_csrf";

	private static final String DEFAULT_CSRF_HEADER_NAME = "X-CSRF-TOKEN";

	private static final String DEFAULT_CSRF_TOKEN_ATTR_NAME = HttpSessionCsrfTokenRepository.class.getName()
			.concat(".CSRF_TOKEN");

	private String parameterName = DEFAULT_CSRF_PARAMETER_NAME;

	private String headerName = DEFAULT_CSRF_HEADER_NAME;

	private String sessionAttributeName = DEFAULT_CSRF_TOKEN_ATTR_NAME;

	private SecureRandom secureRandom;

	/**
	 * Creates a new instance of {@link HttpSessionCsrfTokenRepository}.
	 */
	public HttpSessionCsrfTokenRepository() {
	}

	private HttpSessionCsrfTokenRepository(SecureRandom secureRandom) {
		Assert.notNull(secureRandom, "secureRandom cannot be null");
		this.secureRandom = secureRandom;
	}

	@Override
	public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
		if (token == null) {
			HttpSession session = request.getSession(false);
			if (session != null) {
				session.removeAttribute(this.sessionAttributeName);
			}
		}
		else {
			HttpSession session = request.getSession();
			session.setAttribute(this.sessionAttributeName, getTokenValue(token));
		}
	}

	@Override
	public CsrfToken loadToken(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		if (session == null) {
			return null;
		}
		String token = getTokenValue(session);
		if (!StringUtils.hasLength(token)) {
			return null;
		}
		return this.isXorRandomSecretEnabled()
				? new DefaultCsrfToken(this.headerName, this.parameterName, token, this.secureRandom)
				: new DefaultCsrfToken(this.headerName, this.parameterName, token);
	}

	@Override
	public CsrfToken generateToken(HttpServletRequest request) {
		return this.isXorRandomSecretEnabled()
				? new DefaultCsrfToken(this.headerName, this.parameterName, createNewToken(), this.secureRandom)
				: new DefaultCsrfToken(this.headerName, this.parameterName, createNewToken());
	}

	/**
	 * Sets the {@link HttpServletRequest} parameter name that the {@link CsrfToken} is
	 * expected to appear on
	 * @param parameterName the new parameter name to use
	 */
	public void setParameterName(String parameterName) {
		Assert.hasLength(parameterName, "parameterName cannot be null or empty");
		this.parameterName = parameterName;
	}

	/**
	 * Sets the header name that the {@link CsrfToken} is expected to appear on and the
	 * header that the response will contain the {@link CsrfToken}.
	 * @param headerName the new header name to use
	 */
	public void setHeaderName(String headerName) {
		Assert.hasLength(headerName, "headerName cannot be null or empty");
		this.headerName = headerName;
	}

	/**
	 * Sets the {@link HttpSession} attribute name that the {@link CsrfToken} is stored in
	 * @param sessionAttributeName the new attribute name to use
	 */
	public void setSessionAttributeName(String sessionAttributeName) {
		Assert.hasLength(sessionAttributeName, "sessionAttributename cannot be null or empty");
		this.sessionAttributeName = sessionAttributeName;
	}

	/**
	 * Factory method to create an instance of {@link HttpSessionCsrfTokenRepository} that
	 * has {@link #setXorRandomSecretEnabled(boolean)} set to {@code true}.
	 * @return an instance of {@link HttpSessionCsrfTokenRepository} with
	 * {@link #setXorRandomSecretEnabled(boolean)} set to {@code true}
	 */
	public static HttpSessionCsrfTokenRepository withXorRandomSecretEnabled() {
		HttpSessionCsrfTokenRepository result = new HttpSessionCsrfTokenRepository();
		result.setXorRandomSecretEnabled(true);
		return result;
	}

	/**
	 * Factory method to create an instance of {@link HttpSessionCsrfTokenRepository} that
	 * has {@link #setXorRandomSecretEnabled(boolean)} set to {@code true}.
	 * @param secureRandom the {@link SecureRandom} to use for generating random secrets
	 * @return an instance of {@link HttpSessionCsrfTokenRepository} with
	 * {@link #setXorRandomSecretEnabled(boolean)} set to {@code true}
	 */
	public static HttpSessionCsrfTokenRepository withXorRandomSecretEnabled(SecureRandom secureRandom) {
		return new HttpSessionCsrfTokenRepository(secureRandom);
	}

	/**
	 * Enables generating random secrets to XOR with the csrf token on each request.
	 * @param enabled {@code true} sets the {@link SecureRandom} used for generating
	 * random secrets, {@code false} causes it to be set to null
	 */
	public void setXorRandomSecretEnabled(boolean enabled) {
		if (enabled) {
			this.secureRandom = new SecureRandom();
		}
		else {
			this.secureRandom = null;
		}
	}

	private boolean isXorRandomSecretEnabled() {
		return (this.secureRandom != null);
	}

	private String getTokenValue(CsrfToken token) {
		if (token instanceof DefaultCsrfToken) {
			return ((DefaultCsrfToken) token).getRawToken();
		}
		return token.getToken();
	}

	private String getTokenValue(HttpSession session) {
		Object attributeValue = session.getAttribute(this.sessionAttributeName);
		if (attributeValue instanceof CsrfToken) {
			return ((CsrfToken) attributeValue).getToken();
		}
		return (String) attributeValue;
	}

	private String createNewToken() {
		return UUID.randomUUID().toString();
	}

}
