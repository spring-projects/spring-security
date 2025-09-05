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
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} implementation for the OAuth 2.0 Authorization Consent used
 * in the Authorization Code Grant.
 *
 * @author Joe Grandja
 * @since 0.4.0
 * @see OAuth2AuthorizationConsentAuthenticationProvider
 * @see OAuth2AuthorizationCodeRequestAuthenticationProvider
 */
public class OAuth2AuthorizationConsentAuthenticationToken extends AbstractAuthenticationToken {

	@Serial
	private static final long serialVersionUID = -2111287271882598208L;

	private final String authorizationUri;

	private final String clientId;

	private final Authentication principal;

	private final String state;

	private final Set<String> scopes;

	private final Map<String, Object> additionalParameters;

	/**
	 * Constructs an {@code OAuth2AuthorizationConsentAuthenticationToken} using the
	 * provided parameters.
	 * @param authorizationUri the authorization URI
	 * @param clientId the client identifier
	 * @param principal the {@code Principal} (Resource Owner)
	 * @param state the state
	 * @param scopes the requested (or authorized) scope(s)
	 * @param additionalParameters the additional parameters
	 */
	public OAuth2AuthorizationConsentAuthenticationToken(String authorizationUri, String clientId,
			Authentication principal, String state, @Nullable Set<String> scopes,
			@Nullable Map<String, Object> additionalParameters) {
		super(Collections.emptyList());
		Assert.hasText(authorizationUri, "authorizationUri cannot be empty");
		Assert.hasText(clientId, "clientId cannot be empty");
		Assert.notNull(principal, "principal cannot be null");
		Assert.hasText(state, "state cannot be empty");
		this.authorizationUri = authorizationUri;
		this.clientId = clientId;
		this.principal = principal;
		this.state = state;
		this.scopes = Collections.unmodifiableSet((scopes != null) ? new HashSet<>(scopes) : Collections.emptySet());
		this.additionalParameters = Collections.unmodifiableMap(
				(additionalParameters != null) ? new HashMap<>(additionalParameters) : Collections.emptyMap());
		setAuthenticated(true);
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	/**
	 * Returns the authorization URI.
	 * @return the authorization URI
	 */
	public String getAuthorizationUri() {
		return this.authorizationUri;
	}

	/**
	 * Returns the client identifier.
	 * @return the client identifier
	 */
	public String getClientId() {
		return this.clientId;
	}

	/**
	 * Returns the state.
	 * @return the state
	 */
	public String getState() {
		return this.state;
	}

	/**
	 * Returns the requested (or authorized) scope(s).
	 * @return the requested (or authorized) scope(s), or an empty {@code Set} if not
	 * available
	 */
	public Set<String> getScopes() {
		return this.scopes;
	}

	/**
	 * Returns the additional parameters.
	 * @return the additional parameters, or an empty {@code Map} if not available
	 */
	public Map<String, Object> getAdditionalParameters() {
		return this.additionalParameters;
	}

}
