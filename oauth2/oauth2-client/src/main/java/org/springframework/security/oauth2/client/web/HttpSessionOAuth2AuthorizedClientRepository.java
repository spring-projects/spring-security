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

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.util.Assert;

/**
 * An implementation of an {@link OAuth2AuthorizedClientRepository} that stores
 * {@link OAuth2AuthorizedClient}'s in the {@code HttpSession}.
 *
 * @author Joe Grandja
 * @since 5.1
 * @see OAuth2AuthorizedClientRepository
 * @see OAuth2AuthorizedClient
 */
public final class HttpSessionOAuth2AuthorizedClientRepository implements OAuth2AuthorizedClientRepository {

	private static final String DEFAULT_AUTHORIZED_CLIENTS_ATTR_NAME = HttpSessionOAuth2AuthorizedClientRepository.class
			.getName() + ".AUTHORIZED_CLIENTS";

	private final String sessionAttributeName = DEFAULT_AUTHORIZED_CLIENTS_ATTR_NAME;

	@SuppressWarnings("unchecked")
	@Override
	public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId,
			Authentication principal, HttpServletRequest request) {
		Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
		Assert.notNull(request, "request cannot be null");
		return (T) this.getAuthorizedClients(request).get(clientRegistrationId);
	}

	@Override
	public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal,
			HttpServletRequest request, HttpServletResponse response) {
		Assert.notNull(authorizedClient, "authorizedClient cannot be null");
		Assert.notNull(request, "request cannot be null");
		Assert.notNull(response, "response cannot be null");
		Map<String, OAuth2AuthorizedClient> authorizedClients = this.getAuthorizedClients(request);
		authorizedClients.put(authorizedClient.getClientRegistration().getRegistrationId(), authorizedClient);
		request.getSession().setAttribute(this.sessionAttributeName, authorizedClients);
	}

	@Override
	public void removeAuthorizedClient(String clientRegistrationId, Authentication principal,
			HttpServletRequest request, HttpServletResponse response) {
		Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
		Assert.notNull(request, "request cannot be null");
		Map<String, OAuth2AuthorizedClient> authorizedClients = this.getAuthorizedClients(request);
		if (!authorizedClients.isEmpty()) {
			if (authorizedClients.remove(clientRegistrationId) != null) {
				if (!authorizedClients.isEmpty()) {
					request.getSession().setAttribute(this.sessionAttributeName, authorizedClients);
				}
				else {
					request.getSession().removeAttribute(this.sessionAttributeName);
				}
			}
		}
	}

	@SuppressWarnings("unchecked")
	private Map<String, OAuth2AuthorizedClient> getAuthorizedClients(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		Map<String, OAuth2AuthorizedClient> authorizedClients = (session != null)
				? (Map<String, OAuth2AuthorizedClient>) session.getAttribute(this.sessionAttributeName) : null;
		if (authorizedClients == null) {
			authorizedClients = new HashMap<>();
		}
		return authorizedClients;
	}

}
