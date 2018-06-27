/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.web;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * An implementation of an {@link OAuth2AuthorizedClientRepository} that
 * delegates to the provided {@link OAuth2AuthorizedClientService} if the current
 * {@code Principal} is authenticated, otherwise,
 * to a {@code HttpSession}-backed {@link OAuth2AuthorizedClientRepository}
 * if the current request is unauthenticated (or anonymous).
 *
 * @author Joe Grandja
 * @since 5.1
 * @see OAuth2AuthorizedClientRepository
 * @see OAuth2AuthorizedClient
 * @see OAuth2AuthorizedClientService
 * @see HttpSessionOAuth2AuthorizedClientRepository
 */
public final class AuthenticatedPrincipalOAuth2AuthorizedClientRepository implements OAuth2AuthorizedClientRepository {
	private final OAuth2AuthorizedClientService authorizedClientService;
	protected OAuth2AuthorizedClientRepository httpSessionAuthorizedClientRepository =
			new HttpSessionOAuth2AuthorizedClientRepository();

	/**
	 * Constructs a {@code AuthenticatedPrincipalOAuth2AuthorizedClientRepository} using the provided parameters.
	 *
	 * @param authorizedClientService the authorized client service
	 */
	public AuthenticatedPrincipalOAuth2AuthorizedClientRepository(OAuth2AuthorizedClientService authorizedClientService) {
		Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
		this.authorizedClientService = authorizedClientService;
	}

	@Override
	public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, String principalName,
																		HttpServletRequest request) {
		if (this.isCurrentPrincipalAuthenticated()) {
			return this.authorizedClientService.loadAuthorizedClient(clientRegistrationId, principalName);
		} else {
			return this.httpSessionAuthorizedClientRepository.loadAuthorizedClient(clientRegistrationId, principalName, request);
		}
	}

	@Override
	public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal,
										HttpServletRequest request, HttpServletResponse response) {
		if (this.isCurrentPrincipalAuthenticated()) {
			this.authorizedClientService.saveAuthorizedClient(authorizedClient, principal);
		} else {
			this.httpSessionAuthorizedClientRepository.saveAuthorizedClient(authorizedClient, principal, request, response);
		}
	}

	@Override
	public void removeAuthorizedClient(String clientRegistrationId, String principalName,
										HttpServletRequest request, HttpServletResponse response) {
		if (this.isCurrentPrincipalAuthenticated()) {
			this.authorizedClientService.removeAuthorizedClient(clientRegistrationId, principalName);
		} else {
			this.httpSessionAuthorizedClientRepository.removeAuthorizedClient(clientRegistrationId, principalName, request, response);
		}
	}

	private boolean isCurrentPrincipalAuthenticated() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		return authentication != null &&
				!AnonymousAuthenticationToken.class.isAssignableFrom(authentication.getClass()) &&
				authentication.isAuthenticated();
	}
}
