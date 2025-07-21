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

import java.io.Serial;

/**
 * Thrown if an authentication request is rejected because the account has expired. Makes
 * no assertion as to whether or not the credentials were valid.
 *
 * @author Ben Alex
 */
public class AccountExpiredException extends AccountStatusException {

	@Serial
	private static final long serialVersionUID = 3732869526329993353L;

	/**
	 * Constructs a <code>AccountExpiredException</code> with the specified message.
	 * @param msg the detail message
	 */
	public AccountExpiredException(String msg) {
		super(msg);
	}

	/**
	 * Constructs a <code>AccountExpiredException</code> with the specified message and
	 * root cause.
	 * @param msg the detail message
	 * @param cause root cause
	 */
	public AccountExpiredException(String msg, Throwable cause) {
		super(msg, cause);
	}

}
