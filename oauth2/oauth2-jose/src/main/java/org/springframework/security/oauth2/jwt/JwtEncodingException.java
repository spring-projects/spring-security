/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.oauth2.jwt;

import java.io.Serial;

/**
 * This exception is thrown when an error occurs while attempting to encode a JSON Web
 * Token (JWT).
 *
 * @author Joe Grandja
 * @since 5.6
 */
public class JwtEncodingException extends JwtException {

	@Serial
	private static final long serialVersionUID = 6581840872589902213L;

	/**
	 * Constructs a {@code JwtEncodingException} using the provided parameters.
	 * @param message the detail message
	 */
	public JwtEncodingException(String message) {
		super(message);
	}

	/**
	 * Constructs a {@code JwtEncodingException} using the provided parameters.
	 * @param message the detail message
	 * @param cause the root cause
	 */
	public JwtEncodingException(String message, Throwable cause) {
		super(message, cause);
	}

}
