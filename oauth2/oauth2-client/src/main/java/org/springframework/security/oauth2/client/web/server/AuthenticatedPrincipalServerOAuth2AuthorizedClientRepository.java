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

package org.springframework.security.oauth2.client.web.server;

import reactor.core.publisher.Mono;

import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * An implementation of an {@link ServerOAuth2AuthorizedClientRepository} that delegates
 * to the provided {@link ServerOAuth2AuthorizedClientRepository} if the current
 * {@code Principal} is authenticated, otherwise, to the default (or provided)
 * {@link ServerOAuth2AuthorizedClientRepository} if the current request is
 * unauthenticated (or anonymous). The default
 * {@code ReactiveOAuth2AuthorizedClientRepository} is
 * {@link WebSessionServerOAuth2AuthorizedClientRepository}.
 *
 * @author Rob Winch
 * @since 5.1
 * @see OAuth2AuthorizedClientRepository
 * @see OAuth2AuthorizedClient
 * @see OAuth2AuthorizedClientService
 * @see HttpSessionOAuth2AuthorizedClientRepository
 */
public final class AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository
		implements ServerOAuth2AuthorizedClientRepository {

	private final AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();

	private final ReactiveOAuth2AuthorizedClientService authorizedClientService;

	private ServerOAuth2AuthorizedClientRepository anonymousAuthorizedClientRepository = new WebSessionServerOAuth2AuthorizedClientRepository();

	/**
	 * Creates an instance
	 * @param authorizedClientService the authorized client service
	 */
	public AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository(
			ReactiveOAuth2AuthorizedClientService authorizedClientService) {
		Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
		this.authorizedClientService = authorizedClientService;
	}

	/**
	 * Sets the {@link ServerOAuth2AuthorizedClientRepository} used for requests that are
	 * unauthenticated (or anonymous). The default is
	 * {@link WebSessionServerOAuth2AuthorizedClientRepository}.
	 * @param anonymousAuthorizedClientRepository the repository used for requests that
	 * are unauthenticated (or anonymous)
	 */
	public void setAnonymousAuthorizedClientRepository(
			ServerOAuth2AuthorizedClientRepository anonymousAuthorizedClientRepository) {
		Assert.notNull(anonymousAuthorizedClientRepository, "anonymousAuthorizedClientRepository cannot be null");
		this.anonymousAuthorizedClientRepository = anonymousAuthorizedClientRepository;
	}

	@Override
	public <T extends OAuth2AuthorizedClient> Mono<T> loadAuthorizedClient(String clientRegistrationId,
			Authentication principal, ServerWebExchange exchange) {
		if (this.isPrincipalAuthenticated(principal)) {
			return this.authorizedClientService.loadAuthorizedClient(clientRegistrationId, principal.getName());
		}
		else {
			return this.anonymousAuthorizedClientRepository.loadAuthorizedClient(clientRegistrationId, principal,
					exchange);
		}
	}

	@Override
	public Mono<Void> saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal,
			ServerWebExchange exchange) {
		if (this.isPrincipalAuthenticated(principal)) {
			return this.authorizedClientService.saveAuthorizedClient(authorizedClient, principal);
		}
		else {
			return this.anonymousAuthorizedClientRepository.saveAuthorizedClient(authorizedClient, principal, exchange);
		}
	}

	@Override
	public Mono<Void> removeAuthorizedClient(String clientRegistrationId, Authentication principal,
			ServerWebExchange exchange) {
		if (this.isPrincipalAuthenticated(principal)) {
			return this.authorizedClientService.removeAuthorizedClient(clientRegistrationId, principal.getName());
		}
		else {
			return this.anonymousAuthorizedClientRepository.removeAuthorizedClient(clientRegistrationId, principal,
					exchange);
		}
	}

	private boolean isPrincipalAuthenticated(Authentication authentication) {
		return authentication != null && !this.authenticationTrustResolver.isAnonymous(authentication)
				&& authentication.isAuthenticated();
	}

}
