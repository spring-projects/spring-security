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

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.TestOAuth2RefreshTokens;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AccessTokenResponses;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link RefreshTokenOAuth2AuthorizedClientProvider}.
 *
 * @author Joe Grandja
 */
public class RefreshTokenOAuth2AuthorizedClientProviderTests {
	private ClientRegistrationRepository clientRegistrationRepository;
	private OAuth2AuthorizedClientRepository authorizedClientRepository;
	private RefreshTokenOAuth2AuthorizedClientProvider authorizedClientProvider;
	private OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> accessTokenResponseClient;
	private ClientRegistration clientRegistration;
	private Authentication principal;
	private OAuth2AuthorizedClient authorizedClient;

	@Before
	public void setup() {
		this.clientRegistrationRepository = mock(ClientRegistrationRepository.class);
		this.authorizedClientRepository = mock(OAuth2AuthorizedClientRepository.class);
		this.authorizedClientProvider = new RefreshTokenOAuth2AuthorizedClientProvider(
				this.clientRegistrationRepository, this.authorizedClientRepository);
		this.accessTokenResponseClient = mock(OAuth2AccessTokenResponseClient.class);
		this.authorizedClientProvider.setAccessTokenResponseClient(this.accessTokenResponseClient);
		this.clientRegistration = TestClientRegistrations.clientRegistration().build();
		this.principal = new TestingAuthenticationToken("principal", "password");
		this.authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration, this.principal.getName(),
				TestOAuth2AccessTokens.scopes("read", "write"), TestOAuth2RefreshTokens.refreshToken());
	}

	@Test
	public void constructorWhenClientRegistrationRepositoryIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new RefreshTokenOAuth2AuthorizedClientProvider(null, this.authorizedClientRepository))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("clientRegistrationRepository cannot be null");
	}

	@Test
	public void constructorWhenOAuth2AuthorizedClientRepositoryIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new RefreshTokenOAuth2AuthorizedClientProvider(this.clientRegistrationRepository, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizedClientRepository cannot be null");
	}

	@Test
	public void setAccessTokenResponseClientWhenClientIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientProvider.setAccessTokenResponseClient(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("accessTokenResponseClient cannot be null");
	}

	@Test
	public void authorizeWhenContextIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientProvider.authorize(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("context cannot be null");
	}

	@Test
	public void authorizeWhenNotAuthorizedThenUnableToReauthorize() {
		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.authorize(this.clientRegistration).principal(this.principal).build();
		assertThat(this.authorizedClientProvider.authorize(authorizationContext)).isNull();
	}

	@Test
	public void authorizeWhenAuthorizedAndRefreshTokenIsNullThenUnableToReauthorize() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				this.clientRegistration, this.principal.getName(), this.authorizedClient.getAccessToken());
		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.reauthorize(authorizedClient).principal(this.principal).build();
		assertThat(this.authorizedClientProvider.authorize(authorizationContext)).isNull();
	}

	@Test
	public void authorizeWhenHttpServletRequestIsNullThenThrowIllegalArgumentException() {
		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.reauthorize(this.authorizedClient).principal(this.principal).build();
		assertThatThrownBy(() -> this.authorizedClientProvider.authorize(authorizationContext))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("context.HttpServletRequest cannot be null");
	}

	@Test
	public void authorizeWhenHttpServletResponseIsNullThenThrowIllegalArgumentException() {
		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.reauthorize(this.authorizedClient)
						.principal(this.principal)
						.attribute(HttpServletRequest.class.getName(), new MockHttpServletRequest())
						.build();
		assertThatThrownBy(() -> this.authorizedClientProvider.authorize(authorizationContext))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("context.HttpServletResponse cannot be null");
	}

	@Test
	public void authorizeWhenAuthorizedWithRefreshTokenThenReauthorize() {
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse()
				.refreshToken("new-refresh-token")
				.build();
		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(accessTokenResponse);

		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.reauthorize(this.authorizedClient)
						.principal(this.principal)
						.attribute(HttpServletRequest.class.getName(), new MockHttpServletRequest())
						.attribute(HttpServletResponse.class.getName(), new MockHttpServletResponse())
						.build();

		OAuth2AuthorizedClient authorizedClient = this.authorizedClientProvider.authorize(authorizationContext);

		assertThat(authorizedClient.getClientRegistration()).isSameAs(this.clientRegistration);
		assertThat(authorizedClient.getPrincipalName()).isEqualTo(this.principal.getName());
		assertThat(authorizedClient.getAccessToken()).isEqualTo(accessTokenResponse.getAccessToken());
		assertThat(authorizedClient.getRefreshToken()).isEqualTo(accessTokenResponse.getRefreshToken());
		verify(this.authorizedClientRepository).saveAuthorizedClient(
				eq(authorizedClient), eq(this.principal),
				any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void authorizeWhenAuthorizedAndScopeProvidedThenScopeRequested() {
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse()
				.refreshToken("new-refresh-token")
				.build();
		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(accessTokenResponse);

		Set<String> scope = Collections.singleton("read");

		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.reauthorize(this.authorizedClient)
						.principal(this.principal)
						.attribute(HttpServletRequest.class.getName(), new MockHttpServletRequest())
						.attribute(HttpServletResponse.class.getName(), new MockHttpServletResponse())
						.attribute("SCOPE", scope)
						.build();

		this.authorizedClientProvider.authorize(authorizationContext);

		ArgumentCaptor<OAuth2RefreshTokenGrantRequest> refreshTokenGrantRequestArgCaptor =
				ArgumentCaptor.forClass(OAuth2RefreshTokenGrantRequest.class);
		verify(this.accessTokenResponseClient).getTokenResponse(refreshTokenGrantRequestArgCaptor.capture());
		assertThat(refreshTokenGrantRequestArgCaptor.getValue().getScopes()).isEqualTo(scope);
	}

	@Test
	public void authorizeWhenAuthorizedAndInvalidScopeProvidedThenThrowIllegalArgumentException() {
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse()
				.refreshToken("new-refresh-token")
				.build();
		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(accessTokenResponse);

		String scope = "read";

		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.reauthorize(this.authorizedClient)
						.principal(this.principal)
						.attribute(HttpServletRequest.class.getName(), new MockHttpServletRequest())
						.attribute(HttpServletResponse.class.getName(), new MockHttpServletResponse())
						.attribute("SCOPE", scope)
						.build();

		assertThatThrownBy(() -> this.authorizedClientProvider.authorize(authorizationContext))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("The 'SCOPE' attribute must be of type " + Set.class.getName());
	}
}
