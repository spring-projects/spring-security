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

package org.springframework.security.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * Thrown if an authentication request is rejected because there is no
 * {@link Authentication} object in the
 * {@link org.springframework.security.core.context.SecurityContext SecurityContext}.
 *
 * @author Ben Alex
 */
public class AuthenticationCredentialsNotFoundException extends AuthenticationException {

	/**
	 * Constructs an <code>AuthenticationCredentialsNotFoundException</code> with the
	 * specified message.
	 * @param msg the detail message
	 */
	public AuthenticationCredentialsNotFoundException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>AuthenticationCredentialsNotFoundException</code> with the
	 * specified message and root cause.
	 * @param msg the detail message
	 * @param cause root cause
	 */
	public AuthenticationCredentialsNotFoundException(String msg, Throwable cause) {
		super(msg, cause);
	}

}
