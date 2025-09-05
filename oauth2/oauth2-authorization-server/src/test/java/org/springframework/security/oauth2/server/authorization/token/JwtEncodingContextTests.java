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

package org.springframework.security.oauth2.server.authorization.token;

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.TestJwsHeaders;
import org.springframework.security.oauth2.jwt.TestJwtClaimsSets;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link JwtEncodingContext}.
 *
 * @author Joe Grandja
 */
public class JwtEncodingContextTests {

	@Test
	public void withWhenJwsHeaderNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> JwtEncodingContext.with(null, TestJwtClaimsSets.jwtClaimsSet()))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("jwsHeaderBuilder cannot be null");
	}

	@Test
	public void withWhenClaimsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> JwtEncodingContext.with(TestJwsHeaders.jwsHeader(), null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("claimsBuilder cannot be null");
	}

	@Test
	public void setWhenValueNullThenThrowIllegalArgumentException() {
		JwtEncodingContext.Builder builder = JwtEncodingContext.with(TestJwsHeaders.jwsHeader(),
				TestJwtClaimsSets.jwtClaimsSet());
		assertThatThrownBy(() -> builder.registeredClient(null)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> builder.principal(null)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> builder.authorization(null)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> builder.tokenType(null)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> builder.authorizationGrantType(null)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> builder.authorizationGrant(null)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> builder.put(null, "")).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenAllValuesProvidedThenAllValuesAreSet() {
		JwsHeader.Builder headers = TestJwsHeaders.jwsHeader();
		JwtClaimsSet.Builder claims = TestJwtClaimsSets.jwtClaimsSet();
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		TestingAuthenticationToken principal = new TestingAuthenticationToken("principal", "password");
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
				"code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

		JwtEncodingContext context = JwtEncodingContext.with(headers, claims)
			.registeredClient(registeredClient)
			.principal(principal)
			.authorization(authorization)
			.tokenType(OAuth2TokenType.ACCESS_TOKEN)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.authorizationGrant(authorizationGrant)
			.put("custom-key-1", "custom-value-1")
			.context((ctx) -> ctx.put("custom-key-2", "custom-value-2"))
			.build();

		assertThat(context.getJwsHeader()).isEqualTo(headers);
		assertThat(context.getClaims()).isEqualTo(claims);
		assertThat(context.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(context.<Authentication>getPrincipal()).isEqualTo(principal);
		assertThat(context.getAuthorization()).isEqualTo(authorization);
		assertThat(context.getTokenType()).isEqualTo(OAuth2TokenType.ACCESS_TOKEN);
		assertThat(context.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(context.<OAuth2AuthorizationGrantAuthenticationToken>getAuthorizationGrant())
			.isEqualTo(authorizationGrant);
		assertThat(context.<String>get("custom-key-1")).isEqualTo("custom-value-1");
		assertThat(context.<String>get("custom-key-2")).isEqualTo("custom-value-2");
	}

}
