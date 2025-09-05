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
import java.time.Instant;
import java.util.Map;
import java.util.Set;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} implementation for the OAuth 2.0 Pushed Authorization Request
 * used in the Authorization Code Grant.
 *
 * @author Joe Grandja
 * @since 1.5
 * @see OAuth2PushedAuthorizationRequestAuthenticationProvider
 */
public class OAuth2PushedAuthorizationRequestAuthenticationToken
		extends AbstractOAuth2AuthorizationCodeRequestAuthenticationToken {

	@Serial
	private static final long serialVersionUID = 7330534287786569644L;

	private final String requestUri;

	private final Instant requestUriExpiresAt;

	/**
	 * Constructs an {@code OAuth2PushedAuthorizationRequestAuthenticationToken} using the
	 * provided parameters.
	 * @param authorizationUri the authorization URI
	 * @param clientId the client identifier
	 * @param principal the authenticated client principal
	 * @param redirectUri the redirect uri
	 * @param state the state
	 * @param scopes the requested scope(s)
	 * @param additionalParameters the additional parameters
	 */
	public OAuth2PushedAuthorizationRequestAuthenticationToken(String authorizationUri, String clientId,
			Authentication principal, @Nullable String redirectUri, @Nullable String state,
			@Nullable Set<String> scopes, @Nullable Map<String, Object> additionalParameters) {
		super(authorizationUri, clientId, principal, redirectUri, state, scopes, additionalParameters);
		this.requestUri = null;
		this.requestUriExpiresAt = null;
	}

	/**
	 * Constructs an {@code OAuth2PushedAuthorizationRequestAuthenticationToken} using the
	 * provided parameters.
	 * @param authorizationUri the authorization URI
	 * @param clientId the client identifier
	 * @param principal the authenticated client principal
	 * @param requestUri the {@code request_uri} corresponding to the authorization
	 * request posted
	 * @param requestUriExpiresAt the expiration time on or after which the
	 * {@code request_uri} MUST NOT be accepted
	 * @param redirectUri the redirect uri
	 * @param state the state
	 * @param scopes the authorized scope(s)
	 */
	public OAuth2PushedAuthorizationRequestAuthenticationToken(String authorizationUri, String clientId,
			Authentication principal, String requestUri, Instant requestUriExpiresAt, @Nullable String redirectUri,
			@Nullable String state, @Nullable Set<String> scopes) {
		super(authorizationUri, clientId, principal, redirectUri, state, scopes, null);
		Assert.hasText(requestUri, "requestUri cannot be empty");
		Assert.notNull(requestUriExpiresAt, "requestUriExpiresAt cannot be null");
		this.requestUri = requestUri;
		this.requestUriExpiresAt = requestUriExpiresAt;
		setAuthenticated(true);
	}

	/**
	 * Returns the {@code request_uri} corresponding to the authorization request posted.
	 * @return the {@code request_uri} corresponding to the authorization request posted
	 */
	@Nullable
	public String getRequestUri() {
		return this.requestUri;
	}

	/**
	 * Returns the expiration time on or after which the {@code request_uri} MUST NOT be
	 * accepted.
	 * @return the expiration time on or after which the {@code request_uri} MUST NOT be
	 * accepted
	 */
	@Nullable
	public Instant getRequestUriExpiresAt() {
		return this.requestUriExpiresAt;
	}

}
