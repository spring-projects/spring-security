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
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * An authorization success handler that saves authorized clients in a
 * {@link ServerOAuth2AuthorizedClientRepository}
 * or a {@link ReactiveOAuth2AuthorizedClientService}.
 *
 * @author Phil Clay
 * @since 5.3
 */
public class SaveAuthorizedClientReactiveOAuth2AuthorizationSuccessHandler implements ReactiveOAuth2AuthorizationSuccessHandler {

	/**
	 * A delegate that saves clients in either a
	 * {@link ServerOAuth2AuthorizedClientRepository}
	 * or a
	 * {@link ReactiveOAuth2AuthorizedClientService}.
	 */
	private final ReactiveOAuth2AuthorizationSuccessHandler delegate;

	/**
	 * @param authorizedClientRepository The repository in which authorized clients will be saved.
	 */
	public SaveAuthorizedClientReactiveOAuth2AuthorizationSuccessHandler(final ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
		Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
		this.delegate = (authorizedClient, principal, attributes) ->
				authorizedClientRepository.saveAuthorizedClient(
						authorizedClient,
						principal,
						(ServerWebExchange) attributes.get(ServerWebExchange.class.getName()));
	}

	/**
	 * @param authorizedClientService The service in which authorized clients will be saved.
	 */
	public SaveAuthorizedClientReactiveOAuth2AuthorizationSuccessHandler(final ReactiveOAuth2AuthorizedClientService authorizedClientService) {
		Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
		this.delegate = (authorizedClient, principal, attributes) ->
				authorizedClientService.saveAuthorizedClient(
						authorizedClient,
						principal);
	}

	@Override
	public Mono<Void> onAuthorizationSuccess(
			OAuth2AuthorizedClient authorizedClient,
			Authentication principal,
			Map<String, Object> attributes) {
		return this.delegate.onAuthorizationSuccess(
				authorizedClient,
				principal,
				attributes);
	}
}
