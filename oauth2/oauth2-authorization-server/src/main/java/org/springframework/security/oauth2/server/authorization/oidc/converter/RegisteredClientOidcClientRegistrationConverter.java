/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.oidc.converter;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.util.CollectionUtils;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A {@link Converter} that converts the provided {@link RegisteredClient} to an
 * {@link OidcClientRegistration}.
 *
 * @author Joe Grandja
 * @since 1.2.0
 */
public final class RegisteredClientOidcClientRegistrationConverter
		implements Converter<RegisteredClient, OidcClientRegistration> {

	@Override
	public OidcClientRegistration convert(RegisteredClient registeredClient) {
		// @formatter:off
		OidcClientRegistration.Builder builder = OidcClientRegistration.builder()
				.clientId(registeredClient.getClientId())
				.clientIdIssuedAt(registeredClient.getClientIdIssuedAt())
				.clientName(registeredClient.getClientName());

		if (registeredClient.getClientSecret() != null) {
			builder.clientSecret(registeredClient.getClientSecret());
		}

		if (registeredClient.getClientSecretExpiresAt() != null) {
			builder.clientSecretExpiresAt(registeredClient.getClientSecretExpiresAt());
		}

		builder.redirectUris((redirectUris) ->
				redirectUris.addAll(registeredClient.getRedirectUris()));

		if (!CollectionUtils.isEmpty(registeredClient.getPostLogoutRedirectUris())) {
			builder.postLogoutRedirectUris((postLogoutRedirectUris) ->
					postLogoutRedirectUris.addAll(registeredClient.getPostLogoutRedirectUris()));
		}

		builder.grantTypes((grantTypes) ->
				registeredClient.getAuthorizationGrantTypes().forEach((authorizationGrantType) ->
						grantTypes.add(authorizationGrantType.getValue())));

		if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
			builder.responseType(OAuth2AuthorizationResponseType.CODE.getValue());
		}

		if (!CollectionUtils.isEmpty(registeredClient.getScopes())) {
			builder.scopes((scopes) ->
					scopes.addAll(registeredClient.getScopes()));
		}

		AuthorizationServerContext authorizationServerContext = AuthorizationServerContextHolder.getContext();
		String registrationClientUri = UriComponentsBuilder.fromUriString(authorizationServerContext.getIssuer())
				.path(authorizationServerContext.getAuthorizationServerSettings().getOidcClientRegistrationEndpoint())
				.queryParam(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId())
				.toUriString();

		builder
				.tokenEndpointAuthenticationMethod(registeredClient.getClientAuthenticationMethods().iterator().next().getValue())
				.idTokenSignedResponseAlgorithm(registeredClient.getTokenSettings().getIdTokenSignatureAlgorithm().getName())
				.registrationClientUrl(registrationClientUri);

		ClientSettings clientSettings = registeredClient.getClientSettings();

		if (clientSettings.getJwkSetUrl() != null) {
			builder.jwkSetUrl(clientSettings.getJwkSetUrl());
		}

		if (clientSettings.getTokenEndpointAuthenticationSigningAlgorithm() != null) {
			builder.tokenEndpointAuthenticationSigningAlgorithm(clientSettings.getTokenEndpointAuthenticationSigningAlgorithm().getName());
		}

		return builder.build();
		// @formatter:on
	}

}
