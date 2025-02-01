/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.oauth2.server.resource.introspection;

import java.io.Serial;

/**
 * An exception similar to
 * {@link org.springframework.security.authentication.BadCredentialsException} that
 * indicates an opaque token that is invalid in some way.
 *
 * @author Josh Cummings
 * @since 5.3
 */
public class BadOpaqueTokenException extends OAuth2IntrospectionException {

	@Serial
	private static final long serialVersionUID = -6937847463454551076L;

	public BadOpaqueTokenException(String message) {
		super(message);
	}

	public BadOpaqueTokenException(String message, Throwable cause) {
		super(message, cause);
	}

}
