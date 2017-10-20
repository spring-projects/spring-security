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
package org.springframework.security.oauth2.core.endpoint;

import org.springframework.util.Assert;

/**
 * An &quot;<i>exchange</i>&quot; of an <i>OAuth 2.0 Authorization Request and Response</i>
 * for the authorization code grant type.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AuthorizationRequest
 * @see AuthorizationResponse
 */
public final class AuthorizationExchange {
	private final AuthorizationRequest authorizationRequest;
	private final AuthorizationResponse authorizationResponse;

	public AuthorizationExchange(AuthorizationRequest authorizationRequest,
									AuthorizationResponse authorizationResponse) {
		Assert.notNull(authorizationRequest, "authorizationRequest cannot be null");
		Assert.notNull(authorizationResponse, "authorizationResponse cannot be null");
		this.authorizationRequest = authorizationRequest;
		this.authorizationResponse = authorizationResponse;
	}

	public AuthorizationRequest getAuthorizationRequest() {
		return this.authorizationRequest;
	}

	public AuthorizationResponse getAuthorizationResponse() {
		return this.authorizationResponse;
	}
}
