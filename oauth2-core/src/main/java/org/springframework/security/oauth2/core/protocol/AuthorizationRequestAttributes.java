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
import org.springframework.security.oauth2.core.ResponseType;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.net.URI;
import java.util.Collections;
import java.util.Set;

/**
 * @author Joe Grandja
 */
public class AuthorizationRequestAttributes implements Serializable {
	private final URI authorizeUri;
	private final AuthorizationGrantType authorizationGrantType;
	private final ResponseType responseType;
	private final String clientId;
	private final URI redirectUri;
	private final Set<String> scopes;
	private final String state;

	public AuthorizationRequestAttributes(URI authorizeUri, AuthorizationGrantType authorizationGrantType,
											ResponseType responseType, String clientId, URI redirectUri,
											Set<String> scopes, String state) {

		Assert.notNull(authorizeUri, "authorizeUri cannot be null");
		this.authorizeUri = authorizeUri;

		Assert.notNull(authorizationGrantType, "authorizationGrantType cannot be null");
		Assert.isTrue(AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationGrantType) ||
				AuthorizationGrantType.IMPLICIT.equals(authorizationGrantType), "authorizationGrantType must be either 'authorization_code' or 'implicit'");
		this.authorizationGrantType = authorizationGrantType;

		Assert.notNull(responseType, "responseType cannot be null");
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationGrantType)) {
			Assert.isTrue(ResponseType.CODE.equals(responseType), "responseType must be 'code' for grant type 'authorization_code'");
		} else if (AuthorizationGrantType.IMPLICIT.equals(authorizationGrantType)) {
			Assert.isTrue(ResponseType.TOKEN.equals(responseType), "responseType must be 'token' for grant type 'implicit'");
		}
		this.responseType = responseType;

		Assert.notNull(clientId, "clientId cannot be null");
		this.clientId = clientId;

		this.redirectUri = redirectUri;
		this.scopes = Collections.unmodifiableSet((scopes != null ? scopes : Collections.emptySet()));
		this.state = state;
	}

	public static AuthorizationRequestAttributes authorizationCodeGrant(URI authorizeUri, String clientId,
																		URI redirectUri, Set<String> scopes,
																		String state) {

		return new AuthorizationRequestAttributes(authorizeUri, AuthorizationGrantType.AUTHORIZATION_CODE,
				ResponseType.CODE, clientId, redirectUri, scopes, state);
	}

	public static AuthorizationRequestAttributes implicitGrant(URI authorizeUri, String clientId,
																URI redirectUri, Set<String> scopes,
																String state) {

		return new AuthorizationRequestAttributes(authorizeUri, AuthorizationGrantType.IMPLICIT,
				ResponseType.TOKEN, clientId, redirectUri, scopes, state);
	}

	public final URI getAuthorizeUri() {
		return this.authorizeUri;
	}

	public final AuthorizationGrantType getGrantType() {
		return this.authorizationGrantType;
	}

	public final ResponseType getResponseType() {
		return this.responseType;
	}

	public final String getClientId() {
		return this.clientId;
	}

	public final URI getRedirectUri() {
		return this.redirectUri;
	}

	public final Set<String> getScopes() {
		return this.scopes;
	}

	public final String getState() {
		return this.state;
	}

	public final boolean isAuthorizationCodeGrantType() {
		return AuthorizationGrantType.AUTHORIZATION_CODE.equals(this.getGrantType());
	}

	public final boolean isImplicitGrantType() {
		return AuthorizationGrantType.IMPLICIT.equals(this.getGrantType());
	}
}
