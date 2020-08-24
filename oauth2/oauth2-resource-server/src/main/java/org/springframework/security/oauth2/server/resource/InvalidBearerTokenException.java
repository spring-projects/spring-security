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

package org.springframework.security.oauth2.server.resource;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

/**
 * An {@link OAuth2AuthenticationException} that indicates an invalid bearer token.
 *
 * @author Josh Cummings
 * @since 5.3
 */
public class InvalidBearerTokenException extends OAuth2AuthenticationException {

	/**
	 * Construct an instance of {@link InvalidBearerTokenException} given the provided
	 * description.
	 *
	 * The description will be wrapped into an
	 * {@link org.springframework.security.oauth2.core.OAuth2Error} instance as the
	 * {@code error_description}.
	 * @param description the description
	 */
	public InvalidBearerTokenException(String description) {
		super(BearerTokenErrors.invalidToken(description));
	}

	/**
	 * Construct an instance of {@link InvalidBearerTokenException} given the provided
	 * description and cause
	 *
	 * The description will be wrapped into an
	 * {@link org.springframework.security.oauth2.core.OAuth2Error} instance as the
	 * {@code error_description}.
	 * @param description the description
	 * @param cause the causing exception
	 */
	public InvalidBearerTokenException(String description, Throwable cause) {
		super(BearerTokenErrors.invalidToken(description), cause);
	}

}
