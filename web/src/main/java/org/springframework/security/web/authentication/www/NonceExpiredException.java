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

package org.springframework.security.web.authentication.www;

import java.io.Serial;

import org.springframework.security.core.AuthenticationException;

/**
 * Thrown if an authentication request is rejected because the digest nonce has expired.
 *
 * @author Ben Alex
 */
public class NonceExpiredException extends AuthenticationException {

	@Serial
	private static final long serialVersionUID = -3487244679050681257L;

	/**
	 * Constructs a <code>NonceExpiredException</code> with the specified message.
	 * @param msg the detail message
	 */
	public NonceExpiredException(String msg) {
		super(msg);
	}

	/**
	 * Constructs a <code>NonceExpiredException</code> with the specified message and root
	 * cause.
	 * @param msg the detail message
	 * @param cause root cause
	 */
	public NonceExpiredException(String msg, Throwable cause) {
		super(msg, cause);
	}

}
