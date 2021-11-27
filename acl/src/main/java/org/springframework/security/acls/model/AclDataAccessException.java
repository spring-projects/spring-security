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

package org.springframework.security.acls.model;

/**
 * Abstract base class for Acl data operations.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public abstract class AclDataAccessException extends RuntimeException {

	/**
	 * Constructs an <code>AclDataAccessException</code> with the specified message and
	 * root cause.
	 * @param msg the detail message
	 * @param cause the root cause
	 */
	public AclDataAccessException(String msg, Throwable cause) {
		super(msg, cause);
	}

	/**
	 * Constructs an <code>AclDataAccessException</code> with the specified message and no
	 * root cause.
	 * @param msg the detail message
	 */
	public AclDataAccessException(String msg) {
		super(msg);
	}

}
