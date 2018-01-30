/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client;

/**
 * Base exception for OAuth 2.0 Client related errors.
 *
 * @author Joe Grandja
 * @since 5.1
 */
public class OAuth2ClientException extends RuntimeException {

	/**
	 * Constructs an {@code OAuth2ClientException} using the provided parameters.
	 *
	 * @param message the detail message
	 */
	public OAuth2ClientException(String message) {
		super(message);
	}

	/**
	 * Constructs an {@code OAuth2ClientException} using the provided parameters.
	 *
	 * @param message the detail message
	 * @param cause the root cause
	 */
	public OAuth2ClientException(String message, Throwable cause) {
		super(message, cause);
	}
}
