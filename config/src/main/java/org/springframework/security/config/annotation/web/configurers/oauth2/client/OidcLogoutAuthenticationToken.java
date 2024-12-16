/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers.oauth2.client;

import java.io.Serial;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

/**
 * An {@link org.springframework.security.core.Authentication} instance that represents a
 * request to authenticate an OIDC Logout Token.
 *
 * @author Josh Cummings
 * @since 6.2
 */
class OidcLogoutAuthenticationToken extends AbstractAuthenticationToken {

	@Serial
	private static final long serialVersionUID = -1568528983223505540L;

	private final String logoutToken;

	private final ClientRegistration clientRegistration;

	/**
	 * Construct an {@link OidcLogoutAuthenticationToken}
	 * @param logoutToken a signed, serialized OIDC Logout token
	 * @param clientRegistration the {@link ClientRegistration client} associated with
	 * this token; this is usually derived from material in the logout HTTP request
	 */
	OidcLogoutAuthenticationToken(String logoutToken, ClientRegistration clientRegistration) {
		super(AuthorityUtils.NO_AUTHORITIES);
		this.logoutToken = logoutToken;
		this.clientRegistration = clientRegistration;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getCredentials() {
		return this.logoutToken;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getPrincipal() {
		return this.logoutToken;
	}

	/**
	 * Get the signed, serialized OIDC Logout token
	 * @return the logout token
	 */
	String getLogoutToken() {
		return this.logoutToken;
	}

	/**
	 * Get the {@link ClientRegistration} associated with this logout token
	 * @return the {@link ClientRegistration}
	 */
	ClientRegistration getClientRegistration() {
		return this.clientRegistration;
	}

}
