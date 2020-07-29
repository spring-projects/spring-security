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

package org.springframework.security.oauth2.client;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.util.Assert;

/**
 * An {@link OAuth2AuthorizedClientService} that stores {@link OAuth2AuthorizedClient
 * Authorized Client(s)} in-memory.
 *
 * @author Joe Grandja
 * @author Vedran Pavic
 * @since 5.0
 * @see OAuth2AuthorizedClientService
 * @see OAuth2AuthorizedClient
 * @see OAuth2AuthorizedClientId
 * @see ClientRegistration
 * @see Authentication
 */
public final class InMemoryOAuth2AuthorizedClientService implements OAuth2AuthorizedClientService {

	private final Map<OAuth2AuthorizedClientId, OAuth2AuthorizedClient> authorizedClients;

	private final ClientRegistrationRepository clientRegistrationRepository;

	/**
	 * Constructs an {@code InMemoryOAuth2AuthorizedClientService} using the provided
	 * parameters.
	 * @param clientRegistrationRepository the repository of client registrations
	 */
	public InMemoryOAuth2AuthorizedClientService(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizedClients = new ConcurrentHashMap<>();
	}

	/**
	 * Constructs an {@code InMemoryOAuth2AuthorizedClientService} using the provided
	 * parameters.
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizedClients the initial {@code Map} of authorized client(s) keyed by
	 * {@link OAuth2AuthorizedClientId}
	 * @since 5.2
	 */
	public InMemoryOAuth2AuthorizedClientService(ClientRegistrationRepository clientRegistrationRepository,
			Map<OAuth2AuthorizedClientId, OAuth2AuthorizedClient> authorizedClients) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notEmpty(authorizedClients, "authorizedClients cannot be empty");
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizedClients = new ConcurrentHashMap<>(authorizedClients);
	}

	@Override
	@SuppressWarnings("unchecked")
	public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId,
			String principalName) {
		Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
		Assert.hasText(principalName, "principalName cannot be empty");
		ClientRegistration registration = this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId);
		if (registration == null) {
			return null;
		}
		return (T) this.authorizedClients.get(new OAuth2AuthorizedClientId(clientRegistrationId, principalName));
	}

	@Override
	public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
		Assert.notNull(authorizedClient, "authorizedClient cannot be null");
		Assert.notNull(principal, "principal cannot be null");
		this.authorizedClients.put(new OAuth2AuthorizedClientId(
				authorizedClient.getClientRegistration().getRegistrationId(), principal.getName()), authorizedClient);
	}

	@Override
	public void removeAuthorizedClient(String clientRegistrationId, String principalName) {
		Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
		Assert.hasText(principalName, "principalName cannot be empty");
		ClientRegistration registration = this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId);
		if (registration != null) {
			this.authorizedClients.remove(new OAuth2AuthorizedClientId(clientRegistrationId, principalName));
		}
	}

}
