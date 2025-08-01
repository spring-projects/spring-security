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

package org.springframework.security.oauth2.client.event;

import java.io.Serial;

import org.springframework.context.ApplicationEvent;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.Assert;

/**
 * An event that is published when an {@link OAuth2AuthorizedClient} is refreshed as a
 * result of using a {@code refresh_token} to obtain an OAuth 2.0 Access Token Response.
 *
 * @author Steve Riesenberg
 * @since 6.5
 */
public final class OAuth2AuthorizedClientRefreshedEvent extends ApplicationEvent {

	@Serial
	private static final long serialVersionUID = -2178028089321556476L;

	private final OAuth2AuthorizedClient authorizedClient;

	/**
	 * Creates a new instance with the provided parameters.
	 * @param accessTokenResponse the {@link OAuth2AccessTokenResponse} that triggered the
	 * event
	 * @param authorizedClient the refreshed {@link OAuth2AuthorizedClient}
	 */
	public OAuth2AuthorizedClientRefreshedEvent(OAuth2AccessTokenResponse accessTokenResponse,
			OAuth2AuthorizedClient authorizedClient) {
		super(accessTokenResponse);
		Assert.notNull(authorizedClient, "authorizedClient cannot be null");
		this.authorizedClient = authorizedClient;
	}

	/**
	 * Returns the {@link OAuth2AccessTokenResponse} that triggered the event.
	 * @return the access token response
	 */
	public OAuth2AccessTokenResponse getAccessTokenResponse() {
		return (OAuth2AccessTokenResponse) this.getSource();
	}

	/**
	 * Returns the refreshed {@link OAuth2AuthorizedClient}.
	 * @return the authorized client
	 */
	public OAuth2AuthorizedClient getAuthorizedClient() {
		return this.authorizedClient;
	}

}
