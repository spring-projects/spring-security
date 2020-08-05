/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.web.http;

import java.util.function.Consumer;

import org.springframework.http.HttpHeaders;
import org.springframework.util.Assert;

/**
 * Utilities for interacting with {@link HttpHeaders}
 *
 * @author Rob Winch
 * @since 5.1
 */
public final class SecurityHeaders {

	/**
	 * Sets the provided value as a Bearer token in a header with the name of
	 * {@link HttpHeaders#AUTHORIZATION}
	 * @param bearerTokenValue the bear token value
	 * @return a {@link Consumer} that sets the header.
	 */
	public static Consumer<HttpHeaders> bearerToken(String bearerTokenValue) {
		Assert.hasText(bearerTokenValue, "bearerTokenValue cannot be null");
		return headers -> headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + bearerTokenValue);
	}

	private SecurityHeaders() {
	}

}
