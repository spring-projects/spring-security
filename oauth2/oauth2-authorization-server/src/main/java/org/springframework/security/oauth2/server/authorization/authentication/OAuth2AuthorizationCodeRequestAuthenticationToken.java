/*
 * Copyright 2020-2025 the original author or authors.
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
import java.util.Map;
import java.util.Set;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} implementation for the OAuth 2.0 Authorization Request used
 * in the Authorization Code Grant.
 *
 * @author Joe Grandja
 * @since 0.1.2
 * @see OAuth2AuthorizationCodeRequestAuthenticationProvider
 * @see OAuth2AuthorizationConsentAuthenticationProvider
 */
public class OAuth2AuthorizationCodeRequestAuthenticationToken
		extends AbstractOAuth2AuthorizationCodeRequestAuthenticationToken {

	@Serial
	private static final long serialVersionUID = -1946164725241393094L;

	private final OAuth2AuthorizationCode authorizationCode;

	/**
	 * Constructs an {@code OAuth2AuthorizationCodeRequestAuthenticationToken} using the
	 * provided parameters.
	 * @param authorizationUri the authorization URI
	 * @param clientId the client identifier
	 * @param principal the {@code Principal} (Resource Owner)
	 * @param redirectUri the redirect uri
	 * @param state the state
	 * @param scopes the requested scope(s)
	 * @param additionalParameters the additional parameters
	 * @since 0.4.0
	 */
	public OAuth2AuthorizationCodeRequestAuthenticationToken(String authorizationUri, String clientId,
			Authentication principal, @Nullable String redirectUri, @Nullable String state,
			@Nullable Set<String> scopes, @Nullable Map<String, Object> additionalParameters) {
		super(authorizationUri, clientId, principal, redirectUri, state, scopes, additionalParameters);
		this.authorizationCode = null;
	}

	/**
	 * Constructs an {@code OAuth2AuthorizationCodeRequestAuthenticationToken} using the
	 * provided parameters.
	 * @param authorizationUri the authorization URI
	 * @param clientId the client identifier
	 * @param principal the {@code Principal} (Resource Owner)
	 * @param authorizationCode the {@link OAuth2AuthorizationCode}
	 * @param redirectUri the redirect uri
	 * @param state the state
	 * @param scopes the authorized scope(s)
	 * @since 0.4.0
	 */
	public OAuth2AuthorizationCodeRequestAuthenticationToken(String authorizationUri, String clientId,
			Authentication principal, OAuth2AuthorizationCode authorizationCode, @Nullable String redirectUri,
			@Nullable String state, @Nullable Set<String> scopes) {
		super(authorizationUri, clientId, principal, redirectUri, state, scopes, null);
		Assert.notNull(authorizationCode, "authorizationCode cannot be null");
		this.authorizationCode = authorizationCode;
		setAuthenticated(true);
	}

	/**
	 * Returns the {@link OAuth2AuthorizationCode}.
	 * @return the {@link OAuth2AuthorizationCode}
	 */
	@Nullable
	public OAuth2AuthorizationCode getAuthorizationCode() {
		return this.authorizationCode;
	}

}
