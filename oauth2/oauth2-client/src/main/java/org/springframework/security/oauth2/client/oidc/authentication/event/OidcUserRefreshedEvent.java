/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.oauth2.client.oidc.authentication.event;

import java.io.Serial;

import org.springframework.context.ApplicationEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.util.Assert;

/**
 * An event that is published when an {@link OidcUser} is refreshed as a result of using a
 * {@code refresh_token} to obtain an OAuth 2.0 Access Token Response that contains an
 * {@code id_token}.
 *
 * @author Steve Riesenberg
 * @since 6.5
 * @see org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeAuthenticationProvider
 */
public final class OidcUserRefreshedEvent extends ApplicationEvent {

	@Serial
	private static final long serialVersionUID = 2657442604286019694L;

	private final OidcUser oldOidcUser;

	private final OidcUser newOidcUser;

	private final Authentication authentication;

	/**
	 * Creates a new instance with the provided parameters.
	 * @param accessTokenResponse the {@link OAuth2AccessTokenResponse} that triggered the
	 * event
	 * @param oldOidcUser the original {@link OidcUser}
	 * @param newOidcUser the refreshed {@link OidcUser}
	 * @param authentication the authentication result
	 */
	public OidcUserRefreshedEvent(OAuth2AccessTokenResponse accessTokenResponse, OidcUser oldOidcUser,
			OidcUser newOidcUser, Authentication authentication) {
		super(accessTokenResponse);
		Assert.notNull(oldOidcUser, "oldOidcUser cannot be null");
		Assert.notNull(newOidcUser, "newOidcUser cannot be null");
		Assert.notNull(authentication, "authentication cannot be null");
		this.oldOidcUser = oldOidcUser;
		this.newOidcUser = newOidcUser;
		this.authentication = authentication;
	}

	/**
	 * Returns the {@link OAuth2AccessTokenResponse} that triggered the event.
	 * @return the access token response
	 */
	public OAuth2AccessTokenResponse getAccessTokenResponse() {
		return (OAuth2AccessTokenResponse) this.getSource();
	}

	/**
	 * Returns the original {@link OidcUser}.
	 * @return the original user
	 */
	public OidcUser getOldOidcUser() {
		return this.oldOidcUser;
	}

	/**
	 * Returns the refreshed {@link OidcUser}.
	 * @return the refreshed user
	 */
	public OidcUser getNewOidcUser() {
		return this.newOidcUser;
	}

	/**
	 * Returns the authentication result.
	 * @return the authentication result
	 */
	public Authentication getAuthentication() {
		return this.authentication;
	}

}
