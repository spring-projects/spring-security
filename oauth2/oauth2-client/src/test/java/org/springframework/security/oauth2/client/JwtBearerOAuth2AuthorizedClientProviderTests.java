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

import org.junit.Before;
import org.junit.Test;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.endpoint.JwtBearerGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AccessTokenResponses;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.TestJwts;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link JwtBearerOAuth2AuthorizedClientProvider}.
 *
 * @author Hassene Laaribi
 */
public class JwtBearerOAuth2AuthorizedClientProviderTests {

	private JwtBearerOAuth2AuthorizedClientProvider authorizedClientProvider;

	private OAuth2AccessTokenResponseClient<JwtBearerGrantRequest> accessTokenResponseClient;

	private ClientRegistration clientRegistration;

	private Jwt jwtAssertion;

	private Authentication principal;

	@Before
	public void setup() {
		this.authorizedClientProvider = new JwtBearerOAuth2AuthorizedClientProvider();
		this.accessTokenResponseClient = mock(OAuth2AccessTokenResponseClient.class);
		this.authorizedClientProvider.setAccessTokenResponseClient(this.accessTokenResponseClient);
		// @formatter:off
		this.clientRegistration = ClientRegistration.withRegistrationId("jwt-bearer")
				.clientId("client-id")
				.clientSecret("client-secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
				.scope("read", "write")
				.tokenUri("https://example.com/oauth2/token")
				.build();
		// @formatter:on
		this.jwtAssertion = TestJwts.jwt().build();
		this.principal = new TestingAuthenticationToken(this.jwtAssertion, this.jwtAssertion);
	}

	@Test
	public void setAccessTokenResponseClientWhenClientIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizedClientProvider.setAccessTokenResponseClient(null))
				.withMessage("accessTokenResponseClient cannot be null");
	}

	@Test
	public void authorizeWhenContextIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizedClientProvider.authorize(null))
				.withMessage("context cannot be null");
		// @formatter:on
	}

	@Test
	public void authorizeWhenNotJwtBearerThenUnableToAuthorize() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientCredentials().build();
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(clientRegistration)
				.principal(this.principal)
				.build();
		// @formatter:on
		assertThat(this.authorizedClientProvider.authorize(authorizationContext)).isNull();
	}

	@Test
	public void authorizeWhenJwtBearerAndAuthorizedThenNotAuthorized() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), TestOAuth2AccessTokens.scopes("read", "write"));
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withAuthorizedClient(authorizedClient)
				.principal(this.principal)
				.build();
		// @formatter:on
		assertThat(this.authorizedClientProvider.authorize(authorizationContext)).isNull();
	}

	@Test
	public void authorizeWhenJwtBearerAndNotAuthorizedAndPrincipalNotJwtThenUnableToAuthorize() {
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(this.clientRegistration)
				.principal(new TestingAuthenticationToken("user", "password"))
				.build();
		// @formatter:on
		assertThat(this.authorizedClientProvider.authorize(authorizationContext)).isNull();
	}

	@Test
	public void authorizeWhenJwtBearerAndNotAuthorizedAndPrincipalJwtThenAuthorize() {
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse().build();
		given(this.accessTokenResponseClient.getTokenResponse(any())).willReturn(accessTokenResponse);
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(this.clientRegistration)
				.principal(this.principal)
				.build();
		// @formatter:on
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientProvider.authorize(authorizationContext);
		assertThat(authorizedClient.getClientRegistration()).isSameAs(this.clientRegistration);
		assertThat(authorizedClient.getPrincipalName()).isEqualTo(this.principal.getName());
		assertThat(authorizedClient.getAccessToken()).isEqualTo(accessTokenResponse.getAccessToken());
	}

}
