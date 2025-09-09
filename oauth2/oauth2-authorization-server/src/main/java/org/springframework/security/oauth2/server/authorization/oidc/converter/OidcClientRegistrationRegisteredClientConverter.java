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

import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.util.CollectionUtils;

/**
 * A {@link Converter} that converts the provided {@link OidcClientRegistration} to a
 * {@link RegisteredClient}.
 *
 * @author Joe Grandja
 * @author Dmitriy Dubson
 * @since 7.0
 */
public final class OidcClientRegistrationRegisteredClientConverter
		implements Converter<OidcClientRegistration, RegisteredClient> {

	private static final StringKeyGenerator CLIENT_ID_GENERATOR = new Base64StringKeyGenerator(
			Base64.getUrlEncoder().withoutPadding(), 32);

	private static final StringKeyGenerator CLIENT_SECRET_GENERATOR = new Base64StringKeyGenerator(
			Base64.getUrlEncoder().withoutPadding(), 48);

	@Override
	public RegisteredClient convert(OidcClientRegistration clientRegistration) {
		// @formatter:off
		RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId(CLIENT_ID_GENERATOR.generateKey())
				.clientIdIssuedAt(Instant.now())
				.clientName(clientRegistration.getClientName());

		if (ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue().equals(clientRegistration.getTokenEndpointAuthenticationMethod())) {
			builder
					.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
					.clientSecret(CLIENT_SECRET_GENERATOR.generateKey());
		}
		else if (ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue().equals(clientRegistration.getTokenEndpointAuthenticationMethod())) {
			builder
					.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
					.clientSecret(CLIENT_SECRET_GENERATOR.generateKey());
		}
		else if (ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue().equals(clientRegistration.getTokenEndpointAuthenticationMethod())) {
			builder.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
		}
		else {
			builder
					.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
					.clientSecret(CLIENT_SECRET_GENERATOR.generateKey());
		}

		builder.redirectUris((redirectUris) ->
				redirectUris.addAll(clientRegistration.getRedirectUris()));

		if (!CollectionUtils.isEmpty(clientRegistration.getPostLogoutRedirectUris())) {
			builder.postLogoutRedirectUris((postLogoutRedirectUris) ->
					postLogoutRedirectUris.addAll(clientRegistration.getPostLogoutRedirectUris()));
		}

		if (!CollectionUtils.isEmpty(clientRegistration.getGrantTypes())) {
			builder.authorizationGrantTypes((authorizationGrantTypes) ->
					clientRegistration.getGrantTypes().forEach((grantType) ->
							authorizationGrantTypes.add(new AuthorizationGrantType(grantType))));
		}
		else {
			builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
		}
		if (CollectionUtils.isEmpty(clientRegistration.getResponseTypes()) ||
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

		if (ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue().equals(clientRegistration.getTokenEndpointAuthenticationMethod())) {
			MacAlgorithm macAlgorithm = MacAlgorithm.from(clientRegistration.getTokenEndpointAuthenticationSigningAlgorithm());
			if (macAlgorithm == null) {
				macAlgorithm = MacAlgorithm.HS256;
			}
			clientSettingsBuilder.tokenEndpointAuthenticationSigningAlgorithm(macAlgorithm);
		}
		else if (ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue().equals(clientRegistration.getTokenEndpointAuthenticationMethod())) {
			SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.from(clientRegistration.getTokenEndpointAuthenticationSigningAlgorithm());
			if (signatureAlgorithm == null) {
				signatureAlgorithm = SignatureAlgorithm.RS256;
			}
			clientSettingsBuilder.tokenEndpointAuthenticationSigningAlgorithm(signatureAlgorithm);
			clientSettingsBuilder.jwkSetUrl(clientRegistration.getJwkSetUrl().toString());
		}

		builder
				.clientSettings(clientSettingsBuilder.build())
				.tokenSettings(TokenSettings.builder()
						.idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
						.build());

		return builder.build();
		// @formatter:on
	}

}
