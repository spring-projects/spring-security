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
package org.springframework.security.oauth2.core.protocol;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

import java.net.URI;

/**
 * @author Joe Grandja
 */
public class AuthorizationCodeGrantTokenRequestAttributes extends AbstractTokenRequestAttributes {
	private final String code;
	private final String clientId;
	private final URI redirectUri;

	public AuthorizationCodeGrantTokenRequestAttributes(String code, String clientId, URI redirectUri) {
		super(AuthorizationGrantType.AUTHORIZATION_CODE);

		Assert.notNull(code, "code cannot be null");
		this.code = code;

		Assert.notNull(clientId, "clientId cannot be null");
		this.clientId = clientId;

		this.redirectUri = redirectUri;
	}

	public final String getCode() {
		return this.code;
	}

	public final String getClientId() {
		return this.clientId;
	}

	public final URI getRedirectUri() {
		return this.redirectUri;
	}
}