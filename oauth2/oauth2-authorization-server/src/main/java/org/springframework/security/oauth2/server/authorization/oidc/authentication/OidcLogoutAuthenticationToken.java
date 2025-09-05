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

package org.springframework.security.oauth2.server.authorization.oidc.authentication;

import java.io.Serial;
import java.util.Collections;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} implementation used for OpenID Connect 1.0 RP-Initiated
 * Logout Endpoint.
 *
 * @author Joe Grandja
 * @since 1.1
 * @see AbstractAuthenticationToken
 * @see OidcLogoutAuthenticationProvider
 */
public class OidcLogoutAuthenticationToken extends AbstractAuthenticationToken {

	@Serial
	private static final long serialVersionUID = 4001993612314913888L;

	private final String idTokenHint;

	private final OidcIdToken idToken;

	private final Authentication principal;

	private final String sessionId;

	private final String clientId;

	private final String postLogoutRedirectUri;

	private final String state;

	/**
	 * Constructs an {@code OidcLogoutAuthenticationToken} using the provided parameters.
	 * @param idTokenHint the ID Token previously issued by the Provider to the Client and
	 * used as a hint about the End-User's current authenticated session with the Client
	 * @param principal the authenticated principal representing the End-User
	 * @param sessionId the End-User's current authenticated session identifier with the
	 * Provider
	 * @param clientId the client identifier the ID Token was issued to
	 * @param postLogoutRedirectUri the URI which the Client is requesting that the
	 * End-User's User Agent be redirected to after a logout has been performed
	 * @param state the opaque value used by the Client to maintain state between the
	 * logout request and the callback to the {@code postLogoutRedirectUri}
	 */
	public OidcLogoutAuthenticationToken(String idTokenHint, Authentication principal, @Nullable String sessionId,
			@Nullable String clientId, @Nullable String postLogoutRedirectUri, @Nullable String state) {
		super(Collections.emptyList());
		Assert.hasText(idTokenHint, "idTokenHint cannot be empty");
		Assert.notNull(principal, "principal cannot be null");
		this.idTokenHint = idTokenHint;
		this.idToken = null;
		this.principal = principal;
		this.sessionId = sessionId;
		this.clientId = clientId;
		this.postLogoutRedirectUri = postLogoutRedirectUri;
		this.state = state;
		setAuthenticated(false);
	}

	/**
	 * Constructs an {@code OidcLogoutAuthenticationToken} using the provided parameters.
	 * @param idToken the ID Token previously issued by the Provider to the Client
	 * @param principal the authenticated principal representing the End-User
	 * @param sessionId the End-User's current authenticated session identifier with the
	 * Provider
	 * @param clientId the client identifier the ID Token was issued to
	 * @param postLogoutRedirectUri the URI which the Client is requesting that the
	 * End-User's User Agent be redirected to after a logout has been performed
	 * @param state the opaque value used by the Client to maintain state between the
	 * logout request and the callback to the {@code postLogoutRedirectUri}
	 */
	public OidcLogoutAuthenticationToken(OidcIdToken idToken, Authentication principal, @Nullable String sessionId,
			@Nullable String clientId, @Nullable String postLogoutRedirectUri, @Nullable String state) {
		super(Collections.emptyList());
		Assert.notNull(idToken, "idToken cannot be null");
		Assert.notNull(principal, "principal cannot be null");
		this.idTokenHint = idToken.getTokenValue();
		this.idToken = idToken;
		this.principal = principal;
		this.sessionId = sessionId;
		this.clientId = clientId;
		this.postLogoutRedirectUri = postLogoutRedirectUri;
		this.state = state;
		setAuthenticated(true);
	}

	/**
	 * Returns the authenticated principal representing the End-User.
	 * @return the authenticated principal representing the End-User
	 */
	@Override
	public Object getPrincipal() {
		return this.principal;
	}

	/**
	 * Returns {@code true} if {@link #getPrincipal()} is authenticated, {@code false}
	 * otherwise.
	 * @return {@code true} if {@link #getPrincipal()} is authenticated, {@code false}
	 * otherwise
	 */
	public boolean isPrincipalAuthenticated() {
		return !AnonymousAuthenticationToken.class.isAssignableFrom(this.principal.getClass())
				&& this.principal.isAuthenticated();
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	/**
	 * Returns the ID Token previously issued by the Provider to the Client and used as a
	 * hint about the End-User's current authenticated session with the Client.
	 * @return the ID Token previously issued by the Provider to the Client
	 */
	public String getIdTokenHint() {
		return this.idTokenHint;
	}

	/**
	 * Returns the ID Token previously issued by the Provider to the Client.
	 * @return the ID Token previously issued by the Provider to the Client
	 */
	@Nullable
	public OidcIdToken getIdToken() {
		return this.idToken;
	}

	/**
	 * Returns the End-User's current authenticated session identifier with the Provider.
	 * @return the End-User's current authenticated session identifier with the Provider
	 */
	@Nullable
	public String getSessionId() {
		return this.sessionId;
	}

	/**
	 * Returns the client identifier the ID Token was issued to.
	 * @return the client identifier
	 */
	@Nullable
	public String getClientId() {
		return this.clientId;
	}

	/**
	 * Returns the URI which the Client is requesting that the End-User's User Agent be
	 * redirected to after a logout has been performed.
	 * @return the URI which the Client is requesting that the End-User's User Agent be
	 * redirected to after a logout has been performed
	 */
	@Nullable
	public String getPostLogoutRedirectUri() {
		return this.postLogoutRedirectUri;
	}

	/**
	 * Returns the opaque value used by the Client to maintain state between the logout
	 * request and the callback to the {@link #getPostLogoutRedirectUri()}.
	 * @return the opaque value used by the Client to maintain state between the logout
	 * request and the callback to the {@link #getPostLogoutRedirectUri()}
	 */
	@Nullable
	public String getState() {
		return this.state;
	}

}
