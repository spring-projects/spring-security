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

package org.springframework.security.oauth2.client.event;

import org.springframework.context.ApplicationEvent;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;

/**
 * An event that is published when an OAuth2 access token is refreshed.
 */
public class OAuth2TokenRefreshedEvent extends ApplicationEvent {

	private final OAuth2AuthorizedClient authorizedClient;

	private final OAuth2AccessTokenResponse accessTokenResponse;

	public OAuth2TokenRefreshedEvent(Object source, OAuth2AuthorizedClient authorizedClient,
			OAuth2AccessTokenResponse accessTokenResponse) {
		super(source);
		this.authorizedClient = authorizedClient;
		this.accessTokenResponse = accessTokenResponse;
	}

	public OAuth2AuthorizedClient getAuthorizedClient() {
		return this.authorizedClient;
	}

	public OAuth2AccessTokenResponse getAccessTokenResponse() {
		return this.accessTokenResponse;
	}

}
