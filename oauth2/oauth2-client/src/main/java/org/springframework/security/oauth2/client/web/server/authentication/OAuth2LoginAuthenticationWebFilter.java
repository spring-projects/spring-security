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
package org.springframework.security.oauth2.client.web.server.authentication;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.util.Assert;
import reactor.core.publisher.Mono;

import java.util.Collections;

/**
 * A specialized {@link AuthenticationWebFilter} that converts from an {@link OAuth2LoginAuthenticationToken} to an
 * {@link OAuth2AuthenticationToken} and saves the {@link OAuth2AuthorizedClient}
 *
 * @author Rob Winch
 * @since 5.1
 */
public class OAuth2LoginAuthenticationWebFilter extends AuthenticationWebFilter {

	private final ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

	/**
	 * Creates an instance
	 *
	 * @param authenticationManager the authentication manager to use
	 * @param authorizedClientRepository
	 */
	public OAuth2LoginAuthenticationWebFilter(
			ReactiveAuthenticationManager authenticationManager,
			ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
		super(authenticationManager);
		Assert.notNull(authorizedClientRepository, "authorizedClientService cannot be null");
		this.authorizedClientRepository = authorizedClientRepository;
	}

	@Override
	protected Mono<Void> onAuthenticationSuccess(Authentication authentication,
			WebFilterExchange webFilterExchange) {
		OAuth2LoginAuthenticationToken authenticationResult = (OAuth2LoginAuthenticationToken) authentication;
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				authenticationResult.getClientRegistration(),
				authenticationResult.getName(),
				authenticationResult.getAccessToken(),
				authenticationResult.getRefreshToken(),
				Collections.emptyMap());
		OAuth2AuthenticationToken result =  new OAuth2AuthenticationToken(
				authenticationResult.getPrincipal(),
				authenticationResult.getAuthorities(),
				authenticationResult.getClientRegistration().getRegistrationId());
		return this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, authenticationResult, webFilterExchange.getExchange())
				.then(super.onAuthenticationSuccess(result, webFilterExchange));
	}
}
