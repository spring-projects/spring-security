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

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * The default implementation of an {@link OAuth2AuthorizedClientProvider} that simply
 * {@link OAuth2AuthorizedClientRepository#loadAuthorizedClient(String, Authentication, HttpServletRequest) loads}
 * an {@link OAuth2AuthorizedClient} from the authorized client repository.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see OAuth2AuthorizedClientProvider
 */
public final class DefaultOAuth2AuthorizedClientProvider implements OAuth2AuthorizedClientProvider {
	private static final String HTTP_SERVLET_REQUEST_ATTRIBUTE_NAME = HttpServletRequest.class.getName();
	private static final String HTTP_SERVLET_RESPONSE_ATTRIBUTE_NAME = HttpServletResponse.class.getName();
	private final ClientRegistrationRepository clientRegistrationRepository;
	private final OAuth2AuthorizedClientRepository authorizedClientRepository;

	/**
	 * Constructs an {@code DefaultOAuth2AuthorizedClientProvider} using the provided parameters.
	 *
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizedClientRepository the repository of authorized clients
	 */
	public DefaultOAuth2AuthorizedClientProvider(ClientRegistrationRepository clientRegistrationRepository,
													OAuth2AuthorizedClientRepository authorizedClientRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizedClientRepository = authorizedClientRepository;
	}

	/**
	 * Attempts to {@link OAuth2AuthorizedClientRepository#loadAuthorizedClient(String, Authentication, HttpServletRequest) load}
	 * an {@link OAuth2AuthorizedClient} using the {@link OAuth2AuthorizationContext#getClientRegistrationId() client}
	 * in the provided {@code context}. Returns {@code null} if the client is not authorized.
	 *
	 * <p>
	 * The following {@link OAuth2AuthorizationContext#getAttributes() context attributes} are supported:
	 * <ol>
	 *  <li>{@code "javax.servlet.http.HttpServletRequest"} (required) - the {@code HttpServletRequest}</li>
	 *  <li>{@code "javax.servlet.http.HttpServletResponse"} (required) - the {@code HttpServletResponse}</li>
	 * </ol>
	 *
	 * @param context the context that holds authorization-specific state for the client
	 * @return the {@link OAuth2AuthorizedClient} or {@code null} if the client is not authorized
	 */
	@Override
	@Nullable
	public OAuth2AuthorizedClient authorize(OAuth2AuthorizationContext context) {
		Assert.notNull(context, "context cannot be null");

		HttpServletRequest request = context.getAttribute(HTTP_SERVLET_REQUEST_ATTRIBUTE_NAME);
		HttpServletResponse response = context.getAttribute(HTTP_SERVLET_RESPONSE_ATTRIBUTE_NAME);
		Assert.notNull(request, "The context attribute cannot be null '" + HTTP_SERVLET_REQUEST_ATTRIBUTE_NAME + "'");
		Assert.notNull(response, "The context attribute cannot be null '" + HTTP_SERVLET_RESPONSE_ATTRIBUTE_NAME + "'");

		String clientRegistrationId = context.getClientRegistrationId();
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId);
		Assert.notNull(clientRegistration, "Could not find ClientRegistration with id '" + clientRegistrationId + "'");

		return this.authorizedClientRepository.loadAuthorizedClient(clientRegistrationId, context.getPrincipal(), request);
	}
}
