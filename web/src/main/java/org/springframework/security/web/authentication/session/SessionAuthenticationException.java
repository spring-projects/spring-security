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

package org.springframework.security.web.authentication.session;

import java.io.Serial;

import org.springframework.security.core.AuthenticationException;

/**
 * Thrown by an {@link SessionAuthenticationStrategy} or
 * {@link ServerSessionAuthenticationStrategy} to indicate that an authentication object
 * is not valid for the current session, typically because the same user has exceeded the
 * number of sessions they are allowed to have concurrently.
 *
 * @author Luke Taylor
 * @since 3.0
 * @see SessionAuthenticationStrategy
 * @see ServerSessionAuthenticationStrategy
 */
public class SessionAuthenticationException extends AuthenticationException {

	@Serial
	private static final long serialVersionUID = -2359914603911936474L;

	public SessionAuthenticationException(String msg) {
		super(msg);
	}

}
