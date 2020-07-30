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

import java.util.HashMap;
import java.util.Map;

import reactor.core.publisher.Mono;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;

/**
 * An implementation of an {@link OAuth2AuthorizedClientRepository} that stores
 * {@link OAuth2AuthorizedClient}'s in the {@code HttpSession}.
 *
 * @author Rob Winch
 * @since 5.1
 * @see OAuth2AuthorizedClientRepository
 * @see OAuth2AuthorizedClient
 */
public final class WebSessionServerOAuth2AuthorizedClientRepository implements ServerOAuth2AuthorizedClientRepository {

	private static final String DEFAULT_AUTHORIZED_CLIENTS_ATTR_NAME = WebSessionServerOAuth2AuthorizedClientRepository.class
			.getName() + ".AUTHORIZED_CLIENTS";

	private final String sessionAttributeName = DEFAULT_AUTHORIZED_CLIENTS_ATTR_NAME;

	@Override
	@SuppressWarnings("unchecked")
	public <T extends OAuth2AuthorizedClient> Mono<T> loadAuthorizedClient(String clientRegistrationId,
			Authentication principal, ServerWebExchange exchange) {
		Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
		Assert.notNull(exchange, "exchange cannot be null");
		return exchange.getSession().map(this::getAuthorizedClients)
				.flatMap((clients) -> Mono.justOrEmpty((T) clients.get(clientRegistrationId)));
	}

	@Override
	public Mono<Void> saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal,
			ServerWebExchange exchange) {
		Assert.notNull(authorizedClient, "authorizedClient cannot be null");
		Assert.notNull(exchange, "exchange cannot be null");
		return exchange.getSession().doOnSuccess((session) -> {
			Map<String, OAuth2AuthorizedClient> authorizedClients = getAuthorizedClients(session);
			authorizedClients.put(authorizedClient.getClientRegistration().getRegistrationId(), authorizedClient);
			session.getAttributes().put(this.sessionAttributeName, authorizedClients);
		}).then(Mono.empty());
	}

	@Override
	public Mono<Void> removeAuthorizedClient(String clientRegistrationId, Authentication principal,
			ServerWebExchange exchange) {
		Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
		Assert.notNull(exchange, "exchange cannot be null");
		return exchange.getSession().doOnSuccess((session) -> {
			Map<String, OAuth2AuthorizedClient> authorizedClients = getAuthorizedClients(session);
			authorizedClients.remove(clientRegistrationId);
			if (authorizedClients.isEmpty()) {
				session.getAttributes().remove(this.sessionAttributeName);
			}
			else {
				session.getAttributes().put(this.sessionAttributeName, authorizedClients);
			}
		}).then(Mono.empty());
	}

	@SuppressWarnings("unchecked")
	private Map<String, OAuth2AuthorizedClient> getAuthorizedClients(WebSession session) {
		Map<String, OAuth2AuthorizedClient> authorizedClients = (session != null)
				? (Map<String, OAuth2AuthorizedClient>) session.getAttribute(this.sessionAttributeName) : null;
		if (authorizedClients == null) {
			authorizedClients = new HashMap<>();
		}
		return authorizedClients;
	}

}
