/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.oauth2.client.endpoint;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

/**
 * Base implementation of an <i>OAuth 2.0 Authorization Grant</i> request
 * that holds an <i>authorization grant</i> credential and is used when
 * initiating a HTTP request to the Authorization Server's <i>Token Endpoint</i>.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AuthorizationGrantType
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-1.3">Section 1.3 Authorization Grant</a>
 */
public abstract class AbstractOAuth2AuthorizationGrantRequest {
	private final AuthorizationGrantType authorizationGrantType;

	protected AbstractOAuth2AuthorizationGrantRequest(AuthorizationGrantType authorizationGrantType) {
		Assert.notNull(authorizationGrantType, "authorizationGrantType cannot be null");
		this.authorizationGrantType = authorizationGrantType;
	}

	public AuthorizationGrantType getGrantType() {
		return this.authorizationGrantType;
	}
}
