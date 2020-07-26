/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.web.server.csrf;

import org.springframework.util.Assert;

/**
 * A CSRF token that is used to protect against CSRF attacks.
 *
 * @author Rob Winch
 * @since 5.0
 */
@SuppressWarnings("serial")
public final class DefaultCsrfToken implements CsrfToken {

	private final String token;

	private final String parameterName;

	private final String headerName;

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
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.security.web.csrf.CsrfToken#getHeaderName()
	 */
	@Override
	public String getHeaderName() {
		return this.headerName;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.security.web.csrf.CsrfToken#getParameterName()
	 */
	@Override
	public String getParameterName() {
		return this.parameterName;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.security.web.csrf.CsrfToken#getToken()
	 */
	@Override
	public String getToken() {
		return this.token;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || !(o instanceof CsrfToken)) {
			return false;
		}

		CsrfToken that = (CsrfToken) o;

		if (!getToken().equals(that.getToken())) {
			return false;
		}
		if (!getParameterName().equals(that.getParameterName())) {
			return false;
		}
		return getHeaderName().equals(that.getHeaderName());
	}

	@Override
	public int hashCode() {
		int result = getToken().hashCode();
		result = 31 * result + getParameterName().hashCode();
		result = 31 * result + getHeaderName().hashCode();
		return result;
	}

}
