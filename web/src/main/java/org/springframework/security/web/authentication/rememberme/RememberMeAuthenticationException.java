/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.web.authentication.rememberme;

import org.springframework.security.core.AuthenticationException;

/**
 * This exception is thrown when an
 * {@link org.springframework.security.core.Authentication} exception occurs while using
 * the remember-me authentication.
 *
 * @author Luke Taylor
 */
public class RememberMeAuthenticationException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs a {@code RememberMeAuthenticationException} with the specified message
	 * and root cause.
	 * @param msg the detail message
	 * @param t the root cause
	 */
	public RememberMeAuthenticationException(String msg, Throwable t) {
		super(msg, t);
	}

	/**
	 * Constructs an {@code RememberMeAuthenticationException} with the specified message
	 * and no root cause.
	 * @param msg the detail message
	 */
	public RememberMeAuthenticationException(String msg) {
		super(msg);
	}

}
