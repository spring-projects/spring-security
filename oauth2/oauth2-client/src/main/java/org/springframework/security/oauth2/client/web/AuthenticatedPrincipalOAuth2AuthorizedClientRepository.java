/*
 * Copyright 2002-2018 the original author or authors.
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

import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * An implementation of an {@link OAuth2AuthorizedClientRepository} that
 * delegates to the provided {@link OAuth2AuthorizedClientService} if the current
 * {@code Principal} is authenticated, otherwise,
 * to the default (or provided) {@link OAuth2AuthorizedClientRepository}
 * if the current request is unauthenticated (or anonymous).
 * The default {@code OAuth2AuthorizedClientRepository} is {@link HttpSessionOAuth2AuthorizedClientRepository}.
 *
 * @author Joe Grandja
 * @since 5.1
 * @see OAuth2AuthorizedClientRepository
 * @see OAuth2AuthorizedClient
 * @see OAuth2AuthorizedClientService
 * @see HttpSessionOAuth2AuthorizedClientRepository
 */
public final class AuthenticatedPrincipalOAuth2AuthorizedClientRepository implements OAuth2AuthorizedClientRepository {
	private final AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();
	private final OAuth2AuthorizedClientService authorizedClientService;
	private OAuth2AuthorizedClientRepository anonymousAuthorizedClientRepository = new HttpSessionOAuth2AuthorizedClientRepository();

	/**
	 * Constructs a {@code AuthenticatedPrincipalOAuth2AuthorizedClientRepository} using the provided parameters.
	 *
	 * @param authorizedClientService the authorized client service
	 */
	public AuthenticatedPrincipalOAuth2AuthorizedClientRepository(OAuth2AuthorizedClientService authorizedClientService) {
		Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
		this.authorizedClientService = authorizedClientService;
	}

	/**
	 * Sets the {@link OAuth2AuthorizedClientRepository} used for requests that are unauthenticated (or anonymous).
	 * The default is {@link HttpSessionOAuth2AuthorizedClientRepository}.
	 *
	 * @param anonymousAuthorizedClientRepository the repository used for requests that are unauthenticated (or anonymous)
	 */
	public final void setAnonymousAuthorizedClientRepository(OAuth2AuthorizedClientRepository anonymousAuthorizedClientRepository) {
		Assert.notNull(anonymousAuthorizedClientRepository, "anonymousAuthorizedClientRepository cannot be null");
		this.anonymousAuthorizedClientRepository = anonymousAuthorizedClientRepository;
	}

	@Override
	public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, Authentication principal,
																		HttpServletRequest request) {
		if (this.isPrincipalAuthenticated(principal)) {
			return this.authorizedClientService.loadAuthorizedClient(clientRegistrationId, principal.getName());
		} else {
			return this.anonymousAuthorizedClientRepository.loadAuthorizedClient(clientRegistrationId, principal, request);
		}
	}

	@Override
	public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal,
										HttpServletRequest request, HttpServletResponse response) {
		if (this.isPrincipalAuthenticated(principal)) {
			this.authorizedClientService.saveAuthorizedClient(authorizedClient, principal);
		} else {
			this.anonymousAuthorizedClientRepository.saveAuthorizedClient(authorizedClient, principal, request, response);
		}
	}

	@Override
	public void removeAuthorizedClient(String clientRegistrationId, Authentication principal,
										HttpServletRequest request, HttpServletResponse response) {
		if (this.isPrincipalAuthenticated(principal)) {
			this.authorizedClientService.removeAuthorizedClient(clientRegistrationId, principal.getName());
		} else {
			this.anonymousAuthorizedClientRepository.removeAuthorizedClient(clientRegistrationId, principal, request, response);
		}
	}

	private boolean isPrincipalAuthenticated(Authentication authentication) {
		return authentication != null &&
				!this.authenticationTrustResolver.isAnonymous(authentication) &&
				authentication.isAuthenticated();
	}
}
