/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.core;

import java.io.Serial;

import org.jspecify.annotations.Nullable;

import org.springframework.util.Assert;

/**
 * Abstract superclass for all exceptions related to an {@link Authentication} object
 * being invalid for whatever reason.
 *
 * @author Ben Alex
 */
public abstract class AuthenticationException extends RuntimeException {

	@Serial
	private static final long serialVersionUID = 2018827803361503060L;

	private @Nullable Authentication authenticationRequest;

	/**
	 * Constructs an {@code AuthenticationException} with the specified message and root
	 * cause.
	 * @param msg the detail message
	 * @param cause the root cause
	 */
	public AuthenticationException(@Nullable String msg, Throwable cause) {
		super(msg, cause);
	}

	/**
	 * Constructs an {@code AuthenticationException} with the specified message and no
	 * root cause.
	 * @param msg the detail message
	 */
	public AuthenticationException(@Nullable String msg) {
		super(msg);
	}

	/**
	 * Get the {@link Authentication} object representing the failed authentication
	 * attempt.
	 * <p>
	 * This field captures the authentication request that was attempted but ultimately
	 * failed, providing critical information for diagnosing the failure and facilitating
	 * debugging
	 * @since 6.5
	 */
	public @Nullable Authentication getAuthenticationRequest() {
		return this.authenticationRequest;
	}

	/**
	 * Set the {@link Authentication} object representing the failed authentication
	 * attempt.
	 * <p>
	 * The provided {@code authenticationRequest} should not be null
	 * @param authenticationRequest the authentication request associated with the failed
	 * authentication attempt
	 * @since 6.5
	 */
	public void setAuthenticationRequest(@Nullable Authentication authenticationRequest) {
		Assert.notNull(authenticationRequest, "authenticationRequest cannot be null");
		this.authenticationRequest = authenticationRequest;
	}

}
