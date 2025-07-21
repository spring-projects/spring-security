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

import org.springframework.security.core.AuthenticationException;

/**
 * Thrown by {@link ProviderManager} if no {@link AuthenticationProvider} could be found
 * that supports the presented {@link org.springframework.security.core.Authentication}
 * object.
 *
 * @author Ben Alex
 */
public class ProviderNotFoundException extends AuthenticationException {

	@Serial
	private static final long serialVersionUID = 8107665253214447614L;

	/**
	 * Constructs a <code>ProviderNotFoundException</code> with the specified message.
	 * @param msg the detail message
	 */
	public ProviderNotFoundException(String msg) {
		super(msg);
	}

}
