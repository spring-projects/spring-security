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

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collections;
import java.util.Map;
import java.util.function.BiFunction;

/**
 * The default implementation of an {@link OAuth2AuthorizedClientManager}.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see OAuth2AuthorizedClientManager
 * @see OAuth2AuthorizedClientProvider
 */
public final class DefaultOAuth2AuthorizedClientManager implements OAuth2AuthorizedClientManager {
	private final ClientRegistrationRepository clientRegistrationRepository;
	private final OAuth2AuthorizedClientRepository authorizedClientRepository;
	private OAuth2AuthorizedClientProvider authorizedClientProvider = context -> null;
	private BiFunction<ClientRegistration, HttpServletRequest, Map<String, Object>> contextAttributesMapper =
			(clientRegistration, request) -> Collections.emptyMap();

	/**
	 * Constructs a {@code DefaultOAuth2AuthorizedClientManager} using the provided parameters.
	 *
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizedClientRepository the repository of authorized clients
	 */
	public DefaultOAuth2AuthorizedClientManager(ClientRegistrationRepository clientRegistrationRepository,
												OAuth2AuthorizedClientRepository authorizedClientRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizedClientRepository = authorizedClientRepository;
	}

	@Nullable
	@Override
	public OAuth2AuthorizedClient authorize(String clientRegistrationId, Authentication principal,
											HttpServletRequest request, HttpServletResponse response) {

		Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
		Assert.notNull(principal, "principal cannot be null");
		Assert.notNull(request, "request cannot be null");
		Assert.notNull(response, "response cannot be null");

		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId);
		Assert.notNull(clientRegistration, "Could not find ClientRegistration with id '" + clientRegistrationId + "'");

		OAuth2AuthorizedClient authorizedClient = this.authorizedClientRepository.loadAuthorizedClient(
				clientRegistrationId, principal, request);
		if (authorizedClient != null) {
			return reauthorizeIfNecessary(authorizedClient, principal, request, response);
		}

		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.forClient(clientRegistration)
						.principal(principal)
						.attributes(this.contextAttributesMapper.apply(clientRegistration, request))
						.build();
		authorizedClient = this.authorizedClientProvider.authorize(authorizationContext);
		if (authorizedClient != null) {
			this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, principal, request, response);
		}

		return authorizedClient;
	}

	@Override
	public OAuth2AuthorizedClient reauthorize(OAuth2AuthorizedClient authorizedClient, Authentication principal,
												HttpServletRequest request, HttpServletResponse response) {

		Assert.notNull(authorizedClient, "authorizedClient cannot be null");
		Assert.notNull(principal, "principal cannot be null");
		Assert.notNull(request, "request cannot be null");
		Assert.notNull(response, "response cannot be null");

		return reauthorizeIfNecessary(authorizedClient, principal, request, response);
	}

	private OAuth2AuthorizedClient reauthorizeIfNecessary(OAuth2AuthorizedClient authorizedClient, Authentication principal,
															HttpServletRequest request, HttpServletResponse response) {

		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.forClient(authorizedClient)
						.principal(principal)
						.attributes(this.contextAttributesMapper.apply(authorizedClient.getClientRegistration(), request))
						.build();
		OAuth2AuthorizedClient reauthorizedClient = this.authorizedClientProvider.authorize(authorizationContext);
		if (reauthorizedClient != null) {
			this.authorizedClientRepository.saveAuthorizedClient(reauthorizedClient, principal, request, response);
			return reauthorizedClient;
		}

		return authorizedClient;
	}

	/**
	 * Sets the {@link OAuth2AuthorizedClientProvider} used for authorizing (or re-authorizing) an OAuth 2.0 Client.
	 *
	 * @param authorizedClientProvider the {@link OAuth2AuthorizedClientProvider} used for authorizing (or re-authorizing) an OAuth 2.0 Client
	 */
	public void setAuthorizedClientProvider(OAuth2AuthorizedClientProvider authorizedClientProvider) {
		Assert.notNull(authorizedClientProvider, "authorizedClientProvider cannot be null");
		this.authorizedClientProvider = authorizedClientProvider;
	}

	/**
	 * Sets the {@code BiFunction} used for mapping attribute(s) from the {@link ClientRegistration} and/or {@code HttpServletRequest}
	 * to a {@code Map} of attributes to be associated to the {@link OAuth2AuthorizationContext#getAttributes() authorization context}.
	 *
	 * @param contextAttributesMapper the {@code BiFunction} used for supplying the {@code Map} of attributes
	 *                                   to the {@link OAuth2AuthorizationContext#getAttributes() authorization context}
	 */
	public void setContextAttributesMapper(BiFunction<ClientRegistration, HttpServletRequest, Map<String, Object>> contextAttributesMapper) {
		Assert.notNull(contextAttributesMapper, "contextAttributesMapper cannot be null");
		this.contextAttributesMapper = contextAttributesMapper;
	}
}
