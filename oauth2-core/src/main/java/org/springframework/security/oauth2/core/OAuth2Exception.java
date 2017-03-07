/*
 * Copyright 2012-2017 the original author or authors.
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
package org.springframework.security.oauth2.core;

import org.springframework.security.core.Authentication;

/**
 * Root exception for all OAuth2-related general errors.
 *
 * NOTE:
 * For {@link Authentication} specific errors,
 * use {@link OAuth2AuthenticationException} instead.
 *
 * @author Joe Grandja
 */
public abstract class OAuth2Exception extends RuntimeException {

	public OAuth2Exception() {
		super();
	}

	public OAuth2Exception(String message) {
		super(message);
	}

	public OAuth2Exception(String message, Throwable cause) {
		super(message, cause);
	}
}