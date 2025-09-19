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

package org.springframework.security.oauth2.server.authorization.converter;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.util.CollectionUtils;

/**
 * A {@link Converter} that converts the provided {@link RegisteredClient} to an
 * {@link OAuth2ClientRegistration}.
 *
 * @author Joe Grandja
 * @since 7.0
 */
public final class RegisteredClientOAuth2ClientRegistrationConverter
		implements Converter<RegisteredClient, OAuth2ClientRegistration> {

	@Override
	public OAuth2ClientRegistration convert(RegisteredClient registeredClient) {
		// @formatter:off
		OAuth2ClientRegistration.Builder builder = OAuth2ClientRegistration.builder()
				.clientId(registeredClient.getClientId())
				.clientIdIssuedAt(registeredClient.getClientIdIssuedAt())
				.clientName(registeredClient.getClientName());

		builder
				.tokenEndpointAuthenticationMethod(registeredClient.getClientAuthenticationMethods().iterator().next().getValue());

		if (registeredClient.getClientSecret() != null) {
			builder.clientSecret(registeredClient.getClientSecret());
		}

		if (registeredClient.getClientSecretExpiresAt() != null) {
			builder.clientSecretExpiresAt(registeredClient.getClientSecretExpiresAt());
		}

		if (!CollectionUtils.isEmpty(registeredClient.getRedirectUris())) {
			builder.redirectUris((redirectUris) ->
					redirectUris.addAll(registeredClient.getRedirectUris()));
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

		ClientSettings clientSettings = registeredClient.getClientSettings();

		if (clientSettings.getJwkSetUrl() != null) {
			builder.jwkSetUrl(clientSettings.getJwkSetUrl());
		}

		return builder.build();
		// @formatter:on
	}

}
