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

import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * A {@link Converter} that converts the provided {@link OAuth2ClientRegistration} to a
 * {@link RegisteredClient}.
 *
 * @author Joe Grandja
 * @since 7.0
 */
public final class OAuth2ClientRegistrationRegisteredClientConverter
		implements Converter<OAuth2ClientRegistration, RegisteredClient> {

	private static final StringKeyGenerator CLIENT_ID_GENERATOR = new Base64StringKeyGenerator(
			Base64.getUrlEncoder().withoutPadding(), 32);

	private static final StringKeyGenerator CLIENT_SECRET_GENERATOR = new Base64StringKeyGenerator(
			Base64.getUrlEncoder().withoutPadding(), 48);

	private Consumer<TokenSettings.Builder> tokenSettingsCustomizer = (tokenSettings) -> {
	};

	@Override
	public RegisteredClient convert(OAuth2ClientRegistration clientRegistration) {
		// @formatter:off
		RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId(CLIENT_ID_GENERATOR.generateKey())
				.clientIdIssuedAt(Instant.now());
		String clientName = clientRegistration.getClientName();
		if (clientName != null) {
			builder.clientName(clientName);
		}
		if (ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue().equals(clientRegistration.getTokenEndpointAuthenticationMethod())) {
			builder
					.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
					.clientSecret(CLIENT_SECRET_GENERATOR.generateKey());
		}
		else if (ClientAuthenticationMethod.NONE.getValue().equals(clientRegistration.getTokenEndpointAuthenticationMethod())) {
			builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
		}
		else {
			builder
					.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
					.clientSecret(CLIENT_SECRET_GENERATOR.generateKey());
		}

		if (!CollectionUtils.isEmpty(clientRegistration.getRedirectUris())) {
			builder.redirectUris((redirectUris) ->
					redirectUris.addAll(clientRegistration.getRedirectUris()));
		}

		List<String> grantTypes = clientRegistration.getGrantTypes();
		if (!CollectionUtils.isEmpty(grantTypes)) {
			builder.authorizationGrantTypes((authorizationGrantTypes) ->
					grantTypes.forEach((grantType) ->
							authorizationGrantTypes.add(new AuthorizationGrantType(grantType))));
		}
		else {
			builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
		}

		if (!CollectionUtils.isEmpty(clientRegistration.getResponseTypes()) &&
				clientRegistration.getResponseTypes().contains(OAuth2AuthorizationResponseType.CODE.getValue())) {
			builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
		}

		if (!CollectionUtils.isEmpty(clientRegistration.getScopes())) {
			builder.scopes((scopes) ->
					scopes.addAll(clientRegistration.getScopes()));
		}

		ClientSettings.Builder clientSettingsBuilder = ClientSettings.builder()
				.requireProofKey(true)
				.requireAuthorizationConsent(true);
		if (clientRegistration.getJwkSetUrl() != null) {
			clientSettingsBuilder.jwkSetUrl(clientRegistration.getJwkSetUrl().toString());
		}

		builder
				.clientSettings(clientSettingsBuilder.build());

		TokenSettings.Builder tokenSettingsBuilder = TokenSettings.builder();
		this.tokenSettingsCustomizer.accept(tokenSettingsBuilder);

		builder
				.tokenSettings(tokenSettingsBuilder.build());

		return builder.build();
		// @formatter:on
	}

	/**
	 * Sets the {@code Consumer} providing access to the {@link TokenSettings.Builder}
	 * allowing the ability to customize the token configuration settings.
	 * @param tokenSettingsCustomizer the {@code Consumer} providing access to the
	 * {@link TokenSettings.Builder}
	 * @since 7.1
	 */
	public void setTokenSettingsCustomizer(Consumer<TokenSettings.Builder> tokenSettingsCustomizer) {
		Assert.notNull(tokenSettingsCustomizer, "tokenSettingsCustomizer cannot be null");
		this.tokenSettingsCustomizer = tokenSettingsCustomizer;
	}

}
