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

import io.rsocket.Payload;
import org.springframework.http.MediaType;
import org.springframework.util.MimeType;

/**
 * Represents a username and password that have been encoded into a
 * {@link Payload#metadata()}.
 *
 * @author Rob Winch
 * @since 5.2
 */
public final class UsernamePasswordMetadata {

	/**
	 * Represents a username password which is encoded as
	 * {@code ${username-bytes-length}${username-bytes}${password-bytes}}.
	 *
	 * See <a href="https://github.com/rsocket/rsocket/issues/272">rsocket/rsocket#272</a>
	 * @deprecated Basic did not evolve into the standard. Instead use Simple
	 * Authentication
	 * MimeTypeUtils.parseMimeType(WellKnownMimeType.MESSAGE_RSOCKET_AUTHENTICATION.getString())
	 */
	@Deprecated
	public static final MimeType BASIC_AUTHENTICATION_MIME_TYPE = new MediaType("message",
			"x.rsocket.authentication.basic.v0");

	private final String username;

	private final String password;

	public UsernamePasswordMetadata(String username, String password) {
		this.username = username;
		this.password = password;
	}

	public String getUsername() {
		return this.username;
	}

	public String getPassword() {
		return this.password;
	}

}
