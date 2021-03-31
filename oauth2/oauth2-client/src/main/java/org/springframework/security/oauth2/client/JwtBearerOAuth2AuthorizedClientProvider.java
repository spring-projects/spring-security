/*
 * Copyright 2002-2021 the original author or authors.
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
import org.springframework.security.oauth2.client.endpoint.DefaultJwtBearerTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.JwtBearerGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

/**
 * An implementation of an {@link OAuth2AuthorizedClientProvider} for the
 * {@link AuthorizationGrantType#JWT_BEARER jwt-bearer} grant.
 *
 * @author Joe Grandja
 * @since 5.5
 * @see OAuth2AuthorizedClientProvider
 * @see DefaultJwtBearerTokenResponseClient
 */
public final class JwtBearerOAuth2AuthorizedClientProvider implements OAuth2AuthorizedClientProvider {

	private OAuth2AccessTokenResponseClient<JwtBearerGrantRequest> accessTokenResponseClient = new DefaultJwtBearerTokenResponseClient();

	/**
	 * Attempt to authorize the {@link OAuth2AuthorizationContext#getClientRegistration()
	 * client} in the provided {@code context}. Returns {@code null} if authorization is
	 * not supported, e.g. the client's
	 * {@link ClientRegistration#getAuthorizationGrantType() authorization grant type} is
	 * not {@link AuthorizationGrantType#JWT_BEARER jwt-bearer}.
	 * @param context the context that holds authorization-specific state for the client
	 * @return the {@link OAuth2AuthorizedClient} or {@code null} if authorization is not
	 * supported
	 */
	@Override
	@Nullable
	public OAuth2AuthorizedClient authorize(OAuth2AuthorizationContext context) {
		Assert.notNull(context, "context cannot be null");
		ClientRegistration clientRegistration = context.getClientRegistration();
		if (!AuthorizationGrantType.JWT_BEARER.equals(clientRegistration.getAuthorizationGrantType())) {
			return null;
		}
		OAuth2AuthorizedClient authorizedClient = context.getAuthorizedClient();
		if (authorizedClient != null) {
			// Client is already authorized
			return null;
		}
		if (!(context.getPrincipal().getPrincipal() instanceof Jwt)) {
			return null;
		}
		Jwt jwt = (Jwt) context.getPrincipal().getPrincipal();
		// As per spec, in section 4.1 Using Assertions as Authorization Grants
		// https://tools.ietf.org/html/rfc7521#section-4.1
		//
		// An assertion used in this context is generally a short-lived
		// representation of the authorization grant, and authorization servers
		// SHOULD NOT issue access tokens with a lifetime that exceeds the
		// validity period of the assertion by a significant period. In
		// practice, that will usually mean that refresh tokens are not issued
		// in response to assertion grant requests, and access tokens will be
		// issued with a reasonably short lifetime. Clients can refresh an
		// expired access token by requesting a new one using the same
		// assertion, if it is still valid, or with a new assertion.
		JwtBearerGrantRequest jwtBearerGrantRequest = new JwtBearerGrantRequest(clientRegistration, jwt);
		OAuth2AccessTokenResponse tokenResponse = getTokenResponse(clientRegistration, jwtBearerGrantRequest);
		return new OAuth2AuthorizedClient(clientRegistration, context.getPrincipal().getName(),
				tokenResponse.getAccessToken());
	}

	private OAuth2AccessTokenResponse getTokenResponse(ClientRegistration clientRegistration,
			JwtBearerGrantRequest jwtBearerGrantRequest) {
		try {
			return this.accessTokenResponseClient.getTokenResponse(jwtBearerGrantRequest);
		}
		catch (OAuth2AuthorizationException ex) {
			throw new ClientAuthorizationException(ex.getError(), clientRegistration.getRegistrationId(), ex);
		}
	}

	/**
	 * Sets the client used when requesting an access token credential at the Token
	 * Endpoint for the {@code jwt-bearer} grant.
	 * @param accessTokenResponseClient the client used when requesting an access token
	 * credential at the Token Endpoint for the {@code jwt-bearer} grant
	 */
	public void setAccessTokenResponseClient(
			OAuth2AccessTokenResponseClient<JwtBearerGrantRequest> accessTokenResponseClient) {
		Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
		this.accessTokenResponseClient = accessTokenResponseClient;
	}

}
