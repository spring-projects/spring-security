/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.oauth2.client;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.oidc.OidcAuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.util.Assert;

import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * An {@link OAuth2AuthorizedClientService} that stores
 * {@link OAuth2AuthorizedClient Authorized Client(s)} <i>in-memory</i>.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2AuthorizedClientService
 * @see OAuth2AuthorizedClient
 * @see OidcAuthorizedClient
 * @see ClientRegistration
 * @see Authentication
 *
 * @param <T> The type of <i>OAuth 2.0 Authorized Client</i>
 */
public final class InMemoryOAuth2AuthorizedClientService<T extends OAuth2AuthorizedClient> implements OAuth2AuthorizedClientService<T> {
	private final Map<String, T> authorizedClients = new ConcurrentHashMap<>();
	private final ClientRegistrationRepository clientRegistrationRepository;

	public InMemoryOAuth2AuthorizedClientService(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	@Override
	public T loadAuthorizedClient(String clientRegistrationId, Authentication principal) {
		Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
		Assert.notNull(principal, "principal cannot be null");
		ClientRegistration registration = this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId);
		if (registration == null) {
			return null;
		}
		return this.authorizedClients.get(this.getIdentifier(registration, principal));
	}

	@Override
	public void saveAuthorizedClient(T authorizedClient, Authentication principal) {
		Assert.notNull(authorizedClient, "authorizedClient cannot be null");
		Assert.notNull(principal, "principal cannot be null");
		this.authorizedClients.put(this.getIdentifier(
			authorizedClient.getClientRegistration(), principal), authorizedClient);
	}

	@Override
	public T removeAuthorizedClient(String clientRegistrationId, Authentication principal) {
		Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
		Assert.notNull(principal, "principal cannot be null");
		ClientRegistration registration = this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId);
		if (registration == null) {
			return null;
		}
		return this.authorizedClients.remove(this.getIdentifier(registration, principal));
	}

	private String getIdentifier(ClientRegistration registration, Authentication principal) {
		String identifier = "[" + registration.getRegistrationId() + "][" + principal.getName() + "]";
		return Base64.getEncoder().encodeToString(identifier.getBytes());
	}
}
