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
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Represents a request the {@link OAuth2AuthorizedClientManager} uses to
 * {@link OAuth2AuthorizedClientManager#authorize(OAuth2AuthorizeRequest) authorize} (or re-authorize)
 * the {@link ClientRegistration client} identified by the provided {@link #getClientRegistrationId() clientRegistrationId}.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see OAuth2AuthorizedClientManager
 */
public class OAuth2AuthorizeRequest {
	private final String clientRegistrationId;
	private final OAuth2AuthorizedClient authorizedClient;
	private final Authentication principal;
	private final HttpServletRequest servletRequest;
	private final HttpServletResponse servletResponse;

	/**
	 * Constructs an {@code OAuth2AuthorizeRequest} using the provided parameters.
	 *
	 * @param clientRegistrationId the identifier for the {@link ClientRegistration client registration}
	 * @param principal the {@code Principal} (to be) associated to the authorized client
	 * @param servletRequest the {@code HttpServletRequest}
	 * @param servletResponse the {@code HttpServletResponse}
	 */
	public OAuth2AuthorizeRequest(String clientRegistrationId, Authentication principal,
									HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
		Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
		Assert.notNull(principal, "principal cannot be null");
		Assert.notNull(servletRequest, "servletRequest cannot be null");
		Assert.notNull(servletResponse, "servletResponse cannot be null");
		this.clientRegistrationId = clientRegistrationId;
		this.authorizedClient = null;
		this.principal = principal;
		this.servletRequest = servletRequest;
		this.servletResponse = servletResponse;
	}

	/**
	 * Constructs an {@code OAuth2AuthorizeRequest} using the provided parameters.
	 *
	 * @param authorizedClient the {@link OAuth2AuthorizedClient authorized client}
	 * @param principal the {@code Principal} associated to the authorized client
	 * @param servletRequest the {@code HttpServletRequest}
	 * @param servletResponse the {@code HttpServletResponse}
	 */
	public OAuth2AuthorizeRequest(OAuth2AuthorizedClient authorizedClient, Authentication principal,
									HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
		Assert.notNull(authorizedClient, "authorizedClient cannot be null");
		Assert.notNull(principal, "principal cannot be null");
		Assert.notNull(servletRequest, "servletRequest cannot be null");
		Assert.notNull(servletResponse, "servletResponse cannot be null");
		this.clientRegistrationId = authorizedClient.getClientRegistration().getRegistrationId();
		this.authorizedClient = authorizedClient;
		this.principal = principal;
		this.servletRequest = servletRequest;
		this.servletResponse = servletResponse;
	}

	/**
	 * Returns the identifier for the {@link ClientRegistration client registration}.
	 *
	 * @return the identifier for the client registration
	 */
	public String getClientRegistrationId() {
		return this.clientRegistrationId;
	}

	/**
	 * Returns the {@link OAuth2AuthorizedClient authorized client} or {@code null} if it was not provided.
	 *
	 * @return the {@link OAuth2AuthorizedClient} or {@code null} if it was not provided
	 */
	@Nullable
	public OAuth2AuthorizedClient getAuthorizedClient() {
		return this.authorizedClient;
	}

	/**
	 * Returns the {@code Principal} (to be) associated to the authorized client.
	 *
	 * @return the {@code Principal} (to be) associated to the authorized client
	 */
	public Authentication getPrincipal() {
		return this.principal;
	}

	/**
	 * Returns the {@code HttpServletRequest}.
	 *
	 * @return the {@code HttpServletRequest}
	 */
	public HttpServletRequest getServletRequest() {
		return this.servletRequest;
	}

	/**
	 * Returns the {@code HttpServletResponse}.
	 *
	 * @return the {@code HttpServletResponse}
	 */
	public HttpServletResponse getServletResponse() {
		return this.servletResponse;
	}
}
