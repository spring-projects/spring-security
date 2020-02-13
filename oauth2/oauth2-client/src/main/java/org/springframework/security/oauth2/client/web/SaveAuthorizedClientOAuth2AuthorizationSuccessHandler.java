/*
 * Copyright 2002-2020 the original author or authors.
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
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

/**
 * An {@link OAuth2AuthorizationSuccessHandler} that saves an {@link OAuth2AuthorizedClient}
 * in an {@link OAuth2AuthorizedClientRepository} or {@link OAuth2AuthorizedClientService}.
 *
 * @author Joe Grandja
 * @since 5.3
 * @see OAuth2AuthorizedClient
 * @see OAuth2AuthorizedClientRepository
 * @see OAuth2AuthorizedClientService
 */
public class SaveAuthorizedClientOAuth2AuthorizationSuccessHandler implements OAuth2AuthorizationSuccessHandler {

	/**
	 * A delegate that saves an {@link OAuth2AuthorizedClient} in an
	 * {@link OAuth2AuthorizedClientRepository} or {@link OAuth2AuthorizedClientService}.
	 */
	private final OAuth2AuthorizationSuccessHandler delegate;

	/**
	 * Constructs a {@code SaveAuthorizedClientOAuth2AuthorizationSuccessHandler} using the provided parameters.
	 *
	 * @param authorizedClientRepository The repository in which authorized clients will be saved.
	 */
	public SaveAuthorizedClientOAuth2AuthorizationSuccessHandler(
			OAuth2AuthorizedClientRepository authorizedClientRepository) {
		Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
		this.delegate = (authorizedClient, principal, attributes) ->
				authorizedClientRepository.saveAuthorizedClient(authorizedClient, principal,
						(HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
						(HttpServletResponse) attributes.get(HttpServletResponse.class.getName()));
	}

	/**
	 * Constructs a {@code SaveAuthorizedClientOAuth2AuthorizationSuccessHandler} using the provided parameters.
	 *
	 * @param authorizedClientService The service in which authorized clients will be saved.
	 */
	public SaveAuthorizedClientOAuth2AuthorizationSuccessHandler(
			OAuth2AuthorizedClientService authorizedClientService) {
		Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
		this.delegate = (authorizedClient, principal, attributes) ->
				authorizedClientService.saveAuthorizedClient(authorizedClient, principal);
	}

	@Override
	public void onAuthorizationSuccess(OAuth2AuthorizedClient authorizedClient,
			Authentication principal, Map<String, Object> attributes) {
		this.delegate.onAuthorizationSuccess(authorizedClient, principal, attributes);
	}
}
