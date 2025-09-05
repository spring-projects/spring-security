/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.authentication;

import java.io.Serial;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} implementation for the Device Authorization Consent used in
 * the OAuth 2.0 Device Authorization Grant.
 *
 * @author Steve Riesenberg
 * @since 1.1
 * @see AbstractAuthenticationToken
 * @see OAuth2DeviceAuthorizationConsentAuthenticationProvider
 */
public class OAuth2DeviceAuthorizationConsentAuthenticationToken extends OAuth2AuthorizationConsentAuthenticationToken {

	@Serial
	private static final long serialVersionUID = 3789252233721827596L;

	private final String userCode;

	private final Set<String> requestedScopes;

	/**
	 * Constructs an {@code OAuth2DeviceAuthorizationConsentAuthenticationToken} using the
	 * provided parameters.
	 * @param authorizationUri the authorization URI
	 * @param clientId the client identifier
	 * @param principal the {@code Principal} (Resource Owner)
	 * @param userCode the user code associated with the device authorization response
	 * @param state the state
	 * @param authorizedScopes the authorized scope(s)
	 * @param additionalParameters the additional parameters
	 */
	public OAuth2DeviceAuthorizationConsentAuthenticationToken(String authorizationUri, String clientId,
			Authentication principal, String userCode, String state, @Nullable Set<String> authorizedScopes,
			@Nullable Map<String, Object> additionalParameters) {
		super(authorizationUri, clientId, principal, state, authorizedScopes, additionalParameters);
		Assert.hasText(userCode, "userCode cannot be empty");
		this.userCode = userCode;
		this.requestedScopes = null;
		setAuthenticated(false);
	}

	/**
	 * Constructs an {@code OAuth2DeviceAuthorizationConsentAuthenticationToken} using the
	 * provided parameters.
	 * @param authorizationUri the authorization URI
	 * @param clientId the client identifier
	 * @param principal the {@code Principal} (Resource Owner)
	 * @param userCode the user code associated with the device authorization response
	 * @param state the state
	 * @param requestedScopes the requested scope(s)
	 * @param authorizedScopes the authorized scope(s)
	 */
	public OAuth2DeviceAuthorizationConsentAuthenticationToken(String authorizationUri, String clientId,
			Authentication principal, String userCode, String state, @Nullable Set<String> requestedScopes,
			@Nullable Set<String> authorizedScopes) {
		super(authorizationUri, clientId, principal, state, authorizedScopes, null);
		Assert.hasText(userCode, "userCode cannot be empty");
		this.userCode = userCode;
		this.requestedScopes = Collections
			.unmodifiableSet((requestedScopes != null) ? new HashSet<>(requestedScopes) : Collections.emptySet());
		setAuthenticated(true);
	}

	/**
	 * Returns the user code.
	 * @return the user code
	 */
	public String getUserCode() {
		return this.userCode;
	}

	/**
	 * Returns the requested scopes.
	 * @return the requested scopes
	 */
	public Set<String> getRequestedScopes() {
		return this.requestedScopes;
	}

}
