/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.config.web.server;

import java.util.Collections;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;

/**
 * An {@link org.springframework.security.core.Authentication} implementation that
 * represents the result of authenticating an OIDC Logout token for the purposes of
 * performing Back-Channel Logout.
 *
 * @author Josh Cummings
 * @since 6.2
 * @see OidcLogoutAuthenticationToken
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-backchannel-1_0.html">OIDC Back-Channel
 * Logout</a>
 */
class OidcBackChannelLogoutAuthentication extends AbstractAuthenticationToken {

	private final OidcLogoutToken logoutToken;

	/**
	 * Construct an {@link OidcBackChannelLogoutAuthentication}
	 * @param logoutToken a deserialized, verified OIDC Logout Token
	 */
	OidcBackChannelLogoutAuthentication(OidcLogoutToken logoutToken) {
		super(Collections.emptyList());
		this.logoutToken = logoutToken;
		setAuthenticated(true);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public OidcLogoutToken getPrincipal() {
		return this.logoutToken;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public OidcLogoutToken getCredentials() {
		return this.logoutToken;
	}

}
