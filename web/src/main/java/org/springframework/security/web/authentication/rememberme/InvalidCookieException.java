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

package org.springframework.security.web.authentication.rememberme;

import java.io.Serial;

/**
 * Exception thrown by a RememberMeServices implementation to indicate that a submitted
 * cookie is of an invalid format or has expired.
 *
 * @author Luke Taylor
 */
public class InvalidCookieException extends RememberMeAuthenticationException {

	@Serial
	private static final long serialVersionUID = -7952247791921087125L;

	public InvalidCookieException(String message) {
		super(message);
	}

}
