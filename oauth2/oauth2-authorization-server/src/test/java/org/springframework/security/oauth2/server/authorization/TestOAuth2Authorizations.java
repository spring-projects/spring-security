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

package org.springframework.security.oauth2.server.authorization;

import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.util.CollectionUtils;

/**
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 */
public final class TestOAuth2Authorizations {

	private TestOAuth2Authorizations() {
	}

	public static OAuth2Authorization.Builder authorization() {
		return authorization(TestRegisteredClients.registeredClient().build());
	}

	public static OAuth2Authorization.Builder authorization(RegisteredClient registeredClient) {
		return authorization(registeredClient, Collections.emptyMap());
	}

	public static OAuth2Authorization.Builder authorization(RegisteredClient registeredClient,
			Map<String, Object> authorizationRequestAdditionalParameters) {
		OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode("code", Instant.now(),
				Instant.now().plusSeconds(120));
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token",
				Instant.now(), Instant.now().plusSeconds(300));
		return authorization(registeredClient, authorizationCode, accessToken, Collections.emptyMap(),
				authorizationRequestAdditionalParameters);
	}

	public static OAuth2Authorization.Builder authorization(RegisteredClient registeredClient,
			OAuth2AuthorizationCode authorizationCode) {
		return authorization(registeredClient, authorizationCode, null, Collections.emptyMap(), Collections.emptyMap());
	}

	public static OAuth2Authorization.Builder authorization(RegisteredClient registeredClient,
			OAuth2AccessToken accessToken, Map<String, Object> accessTokenClaims) {
		OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode("code", Instant.now(),
				Instant.now().plusSeconds(120));
		return authorization(registeredClient, authorizationCode, accessToken, accessTokenClaims,
				Collections.emptyMap());
	}

	private static OAuth2Authorization.Builder authorization(RegisteredClient registeredClient,
			OAuth2AuthorizationCode authorizationCode, OAuth2AccessToken accessToken,
			Map<String, Object> accessTokenClaims, Map<String, Object> authorizationRequestAdditionalParameters) {
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
			.authorizationUri("https://provider.com/oauth2/authorize")
			.clientId(registeredClient.getClientId())
			.redirectUri(registeredClient.getRedirectUris().iterator().next())
			.scopes(registeredClient.getScopes())
			.additionalParameters(authorizationRequestAdditionalParameters)
			.state("state")
			.build();
		OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
			.id("id")
			.principalName("principal")
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.authorizedScopes(authorizationRequest.getScopes())
			.token(authorizationCode)
			.attribute(OAuth2ParameterNames.STATE, "consent-state")
			.attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest)
			.attribute(Principal.class.getName(),
					new TestingAuthenticationToken("principal", null, "ROLE_A", "ROLE_B"));
		if (accessToken != null) {
			OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", Instant.now(),
					Instant.now().plus(1, ChronoUnit.HOURS));
			builder
				.token(accessToken, (metadata) -> metadata.putAll(tokenMetadata(registeredClient, accessTokenClaims)))
				.refreshToken(refreshToken);
		}

		return builder;
	}

	private static Map<String, Object> tokenMetadata(RegisteredClient registeredClient,
			Map<String, Object> tokenClaims) {
		Map<String, Object> tokenMetadata = new HashMap<>();
		OAuth2TokenFormat accessTokenFormat = registeredClient.getTokenSettings().getAccessTokenFormat();
		tokenMetadata.put(OAuth2TokenFormat.class.getName(), accessTokenFormat.getValue());
		tokenMetadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false);
		if (CollectionUtils.isEmpty(tokenClaims)) {
			tokenClaims = defaultTokenClaims();
		}
		tokenMetadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, tokenClaims);
		return tokenMetadata;
	}

	private static Map<String, Object> defaultTokenClaims() {
		Map<String, Object> claims = new HashMap<>();
		claims.put("claim1", "value1");
		claims.put("claim2", "value2");
		claims.put("claim3", "value3");
		return claims;
	}

}
