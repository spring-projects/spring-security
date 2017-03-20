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

/**
 * The available authentication methods used when authenticating the client with the authorization server.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-2.3">Section 2.3 Client Authentication</a>
 */
public enum ClientAuthenticationMethod {
	HEADER("header"),
	FORM("form");

	private final String value;

	ClientAuthenticationMethod(String value) {
		this.value = value;
	}

	public String value() {
		return this.value;
	}
}
