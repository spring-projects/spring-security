/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.authentication.password;

import java.io.Serial;

import org.springframework.security.core.AuthenticationException;

/**
 * Indicates that the provided password is compromised
 *
 * @author Marcus da Coregio
 * @since 6.3
 */
public class CompromisedPasswordException extends AuthenticationException {

	@Serial
	private static final long serialVersionUID = -885858958297842864L;

	public CompromisedPasswordException(String message) {
		super(message);
	}

	public CompromisedPasswordException(String message, Throwable cause) {
		super(message, cause);
	}

}
