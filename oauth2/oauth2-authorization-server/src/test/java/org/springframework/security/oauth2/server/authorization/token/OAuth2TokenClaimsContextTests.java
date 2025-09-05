/*
 * Copyright 2020-2022 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.token;

import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.TestAuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OAuth2TokenClaimsContext}.
 *
 * @author Joe Grandja
 */
public class OAuth2TokenClaimsContextTests {

	@Test
	public void withWhenClaimsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OAuth2TokenClaimsContext.with(null)).isInstanceOf(IllegalArgumentException.class)
			.hasMessage("claimsBuilder cannot be null");
	}

	@Test
	public void buildWhenAllValuesProvidedThenAllValuesAreSet() {
		String issuer = "https://provider.com";
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);

		// @formatter:off
		OAuth2TokenClaimsSet.Builder claims = OAuth2TokenClaimsSet.builder()
				.issuer(issuer)
				.subject("subject")
				.audience(Collections.singletonList("client-1"))
				.issuedAt(issuedAt)
				.notBefore(issuedAt)
				.expiresAt(expiresAt)
				.id("id");
		// @formatter:on

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		Authentication principal = authorization.getAttribute(Principal.class.getName());
		AuthorizationServerSettings authorizationServerSettings = AuthorizationServerSettings.builder()
			.issuer(issuer)
			.build();
		AuthorizationServerContext authorizationServerContext = new TestAuthorizationServerContext(
				authorizationServerSettings, null);
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
				"code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

		// @formatter:off
		OAuth2TokenClaimsContext context = OAuth2TokenClaimsContext.with(claims)
				.registeredClient(registeredClient)
				.principal(principal)
				.authorizationServerContext(authorizationServerContext)
				.authorization(authorization)
				.tokenType(OAuth2TokenType.ACCESS_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrant(authorizationGrant)
				.put("custom-key-1", "custom-value-1")
				.context((ctx) -> ctx.put("custom-key-2", "custom-value-2"))
				.build();
		// @formatter:on

		assertThat(context.getClaims()).isEqualTo(claims);
		assertThat(context.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(context.<Authentication>getPrincipal()).isEqualTo(principal);
		assertThat(context.getAuthorizationServerContext()).isEqualTo(authorizationServerContext);
		assertThat(context.getAuthorization()).isEqualTo(authorization);
		assertThat(context.getTokenType()).isEqualTo(OAuth2TokenType.ACCESS_TOKEN);
		assertThat(context.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(context.<OAuth2AuthorizationGrantAuthenticationToken>getAuthorizationGrant())
			.isEqualTo(authorizationGrant);
		assertThat(context.<String>get("custom-key-1")).isEqualTo("custom-value-1");
		assertThat(context.<String>get("custom-key-2")).isEqualTo("custom-value-2");
	}

}
