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
import org.springframework.security.oauth2.client.endpoint.DefaultClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * An implementation of an {@link OAuth2AuthorizedClientProvider}
 * for the {@link AuthorizationGrantType#CLIENT_CREDENTIALS client_credentials} grant.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see OAuth2AuthorizedClientProvider
 * @see DefaultClientCredentialsTokenResponseClient
 */
public final class ClientCredentialsOAuth2AuthorizedClientProvider implements OAuth2AuthorizedClientProvider {
	private static final String HTTP_SERVLET_REQUEST_ATTRIBUTE_NAME = HttpServletRequest.class.getName();
	private static final String HTTP_SERVLET_RESPONSE_ATTRIBUTE_NAME = HttpServletResponse.class.getName();
	private final ClientRegistrationRepository clientRegistrationRepository;
	private final OAuth2AuthorizedClientRepository authorizedClientRepository;
	private OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> accessTokenResponseClient =
			new DefaultClientCredentialsTokenResponseClient();

	/**
	 * Constructs a {@code ClientCredentialsOAuth2AuthorizedClientProvider} using the provided parameters.
	 *
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizedClientRepository the repository of authorized clients
	 */
	public ClientCredentialsOAuth2AuthorizedClientProvider(ClientRegistrationRepository clientRegistrationRepository,
															OAuth2AuthorizedClientRepository authorizedClientRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizedClientRepository = authorizedClientRepository;
	}

	/**
	 * Attempt to authorize (or re-authorize) the {@link OAuth2AuthorizationContext#getClientRegistration() client} in the provided {@code context}.
	 * Returns {@code null} if authorization (or re-authorization) is not supported,
	 * e.g. the client's {@link ClientRegistration#getAuthorizationGrantType() authorization grant type}
	 * is not {@link AuthorizationGrantType#CLIENT_CREDENTIALS client_credentials}.
	 *
	 * <p>
	 * The following {@link OAuth2AuthorizationContext#getAttributes() context attributes} are supported:
	 * <ol>
	 *  <li>{@code "javax.servlet.http.HttpServletRequest"} (required) - the {@code HttpServletRequest}</li>
	 *  <li>{@code "javax.servlet.http.HttpServletResponse"} (required) - the {@code HttpServletResponse}</li>
	 * </ol>
	 *
	 * @param context the context that holds authorization-specific state for the client
	 * @return the {@link OAuth2AuthorizedClient} or {@code null} if authorization (or re-authorization) is not supported
	 */
	@Override
	@Nullable
	public OAuth2AuthorizedClient authorize(OAuth2AuthorizationContext context) {
		Assert.notNull(context, "context cannot be null");
		if (!AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getClientRegistration().getAuthorizationGrantType())) {
			return null;
		}

		HttpServletRequest request = context.getAttribute(HTTP_SERVLET_REQUEST_ATTRIBUTE_NAME);
		HttpServletResponse response = context.getAttribute(HTTP_SERVLET_RESPONSE_ATTRIBUTE_NAME);
		Assert.notNull(request, "The context attribute cannot be null '" + HTTP_SERVLET_REQUEST_ATTRIBUTE_NAME + "'");
		Assert.notNull(response, "The context attribute cannot be null '" + HTTP_SERVLET_RESPONSE_ATTRIBUTE_NAME + "'");

		// As per spec, in section 4.4.3 Access Token Response
		// https://tools.ietf.org/html/rfc6749#section-4.4.3
		// A refresh token SHOULD NOT be included.
		//
		// Therefore, renewing an expired access token (re-authorization)
		// is the same as acquiring a new access token (authorization).

		OAuth2ClientCredentialsGrantRequest clientCredentialsGrantRequest =
				new OAuth2ClientCredentialsGrantRequest(context.getClientRegistration());
		OAuth2AccessTokenResponse tokenResponse =
				this.accessTokenResponseClient.getTokenResponse(clientCredentialsGrantRequest);

		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				context.getClientRegistration(),
				context.getPrincipal().getName(),
				tokenResponse.getAccessToken());

		this.authorizedClientRepository.saveAuthorizedClient(
				authorizedClient,
				context.getPrincipal(),
				request,
				response);

		return authorizedClient;
	}

	/**
	 * Sets the client used when requesting an access token credential at the Token Endpoint for the {@code client_credentials} grant.
	 *
	 * @param accessTokenResponseClient the client used when requesting an access token credential at the Token Endpoint for the {@code client_credentials} grant
	 */
	public void setAccessTokenResponseClient(OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> accessTokenResponseClient) {
		Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
		this.accessTokenResponseClient = accessTokenResponseClient;
	}
}
