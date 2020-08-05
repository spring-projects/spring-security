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

/**
 * Abstract superclass for all exceptions related to an {@link Authentication} object
 * being invalid for whatever reason.
 *
 * @author Ben Alex
 */
public abstract class AuthenticationException extends RuntimeException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an {@code AuthenticationException} with the specified message and root
	 * cause.
	 * @param msg the detail message
	 * @param t the root cause
	 */
	public AuthenticationException(String msg, Throwable t) {
		super(msg, t);
	}

	/**
	 * Constructs an {@code AuthenticationException} with the specified message and no
	 * root cause.
	 * @param msg the detail message
	 */
	public AuthenticationException(String msg) {
		super(msg);
	}

}
