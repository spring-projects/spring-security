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
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} implementation used for OpenID Connect 1.0 Dynamic Client
 * Registration (and Configuration) Endpoint.
 *
 * @author Joe Grandja
 * @author Ovidiu Popa
 * @since 7.0
 * @see AbstractAuthenticationToken
 * @see OidcClientRegistration
 * @see OidcClientRegistrationAuthenticationProvider
 * @see OidcClientConfigurationAuthenticationProvider
 */
public class OidcClientRegistrationAuthenticationToken extends AbstractAuthenticationToken {

	@Serial
	private static final long serialVersionUID = -6198261907690781217L;

	private final Authentication principal;

	private final OidcClientRegistration clientRegistration;

	private final String clientId;

	/**
	 * Constructs an {@code OidcClientRegistrationAuthenticationToken} using the provided
	 * parameters.
	 * @param principal the authenticated principal
	 * @param clientRegistration the client registration
	 */
	public OidcClientRegistrationAuthenticationToken(Authentication principal,
			OidcClientRegistration clientRegistration) {
		super(Collections.emptyList());
		Assert.notNull(principal, "principal cannot be null");
		Assert.notNull(clientRegistration, "clientRegistration cannot be null");
		this.principal = principal;
		this.clientRegistration = clientRegistration;
		this.clientId = null;
		setAuthenticated(principal.isAuthenticated());
	}

	/**
	 * Constructs an {@code OidcClientRegistrationAuthenticationToken} using the provided
	 * parameters.
	 * @param principal the authenticated principal
	 * @param clientId the client identifier
	 */
	public OidcClientRegistrationAuthenticationToken(Authentication principal, String clientId) {
		super(Collections.emptyList());
		Assert.notNull(principal, "principal cannot be null");
		Assert.hasText(clientId, "clientId cannot be empty");
		this.principal = principal;
		this.clientRegistration = null;
		this.clientId = clientId;
		setAuthenticated(principal.isAuthenticated());
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
	 * Returns the client registration.
	 * @return the client registration
	 */
	public OidcClientRegistration getClientRegistration() {
		return this.clientRegistration;
	}

	/**
	 * Returns the client identifier.
	 * @return the client identifier
	 */
	@Nullable
	public String getClientId() {
		return this.clientId;
	}

}
