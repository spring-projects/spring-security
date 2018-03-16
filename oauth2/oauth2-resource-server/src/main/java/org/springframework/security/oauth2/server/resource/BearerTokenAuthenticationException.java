/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.oauth2.server.resource;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Assert;

/**
 * This exception is thrown for all Bearer Token related {@link Authentication} errors.
 *
 * @author Vedran Pavic
 * @since 5.1
 * @see <a href="https://tools.ietf.org/html/rfc6750#section-3" target="_blank">RFC 6750 Section 3: The WWW-Authenticate Response Header Field</a>
 */
public class BearerTokenAuthenticationException extends AuthenticationException {

	private final BearerTokenError error;

	/**
	 * Create a new {@link BearerTokenAuthenticationException}.
	 * @param error the {@link BearerTokenError Bearer Token Error}
	 * @param message the detail message
	 * @param cause the root cause
	 */
	public BearerTokenAuthenticationException(BearerTokenError error, String message, Throwable cause) {
		super(message, cause);
		Assert.notNull(error, "error must not be null");
		this.error = error;
	}

	/**
	 * Create a new {@link BearerTokenAuthenticationException}.
	 * @param error the {@link BearerTokenError Bearer Token Error}
	 * @param message the detail message
	 */
	public BearerTokenAuthenticationException(BearerTokenError error, String message) {
		super(message);
		Assert.notNull(error, "error must not be null");
		this.error = error;
	}

	/**
	 * Return the Bearer Token error
	 * @return the error
	 */
	public BearerTokenError getError() {
		return error;
	}

}
