/*
 * Copyright 2019 the original author or authors.
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


package org.springframework.security.rsocket.metadata;

import org.springframework.http.MediaType;
import org.springframework.util.MimeType;

/**
 * Represents a bearer token that has been encoded into a
 * {@link Payload#metadata()}.
 *
 * @author Rob Winch
 * @since 5.2
 */
public class BearerTokenMetadata {
	/**
	 * Represents a bearer token which is encoded as a String.
	 *
	 * See <a href="https://github.com/rsocket/rsocket/issues/272">rsocket/rsocket#272</a>
	 */
	public static final MimeType BEARER_AUTHENTICATION_MIME_TYPE = new MediaType("message", "x.rsocket.authentication.bearer.v0");

	private final String token;

	public BearerTokenMetadata(String token) {
		this.token = token;
	}

	public String getToken() {
		return this.token;
	}
}
