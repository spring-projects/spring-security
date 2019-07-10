/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.oauth2.client.web;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Represents a request the {@link OAuth2AuthorizedClientManager} uses to
 * {@link OAuth2AuthorizedClientManager#reauthorize(OAuth2ReauthorizeRequest) re-authorize}
 * the provided {@link OAuth2AuthorizedClient#getClientRegistration() client}.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see OAuth2AuthorizeRequest
 * @see OAuth2AuthorizedClientManager
 */
public class OAuth2ReauthorizeRequest extends OAuth2AuthorizeRequest {
	private OAuth2AuthorizedClient authorizedClient;

	public OAuth2ReauthorizeRequest(OAuth2AuthorizedClient authorizedClient, Authentication principal,
									HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
		super(getClientRegistrationId(authorizedClient), principal, servletRequest, servletResponse);
		this.authorizedClient = authorizedClient;
	}

	private static String getClientRegistrationId(OAuth2AuthorizedClient authorizedClient) {
		Assert.notNull(authorizedClient, "authorizedClient cannot be null");
		return authorizedClient.getClientRegistration().getRegistrationId();
	}

	/**
	 * Returns the {@link OAuth2AuthorizedClient authorized client}.
	 *
	 * @return the {@link OAuth2AuthorizedClient}
	 */
	public OAuth2AuthorizedClient getAuthorizedClient() {
		return this.authorizedClient;
	}
}
