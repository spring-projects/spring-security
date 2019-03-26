/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.oauth2.client.authentication;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link OAuth2AuthorizationCodeAuthenticationProvider}.
 *
 * @author Joe Grandja
 */
@PrepareForTest({ClientRegistration.class, OAuth2AuthorizationRequest.class,
	OAuth2AuthorizationResponse.class, OAuth2AccessTokenResponse.class})
@RunWith(PowerMockRunner.class)
public class OAuth2AuthorizationCodeAuthenticationProviderTests {
	private ClientRegistration clientRegistration;
	private OAuth2AuthorizationRequest authorizationRequest;
	private OAuth2AuthorizationResponse authorizationResponse;
	private OAuth2AuthorizationExchange authorizationExchange;
	private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;
	private OAuth2AuthorizationCodeAuthenticationProvider authenticationProvider;

	@Before
	@SuppressWarnings("unchecked")
	public void setUp() throws Exception {
		this.clientRegistration = mock(ClientRegistration.class);
		this.authorizationRequest = mock(OAuth2AuthorizationRequest.class);
		this.authorizationResponse = mock(OAuth2AuthorizationResponse.class);
		this.authorizationExchange = new OAuth2AuthorizationExchange(this.authorizationRequest, this.authorizationResponse);
		this.accessTokenResponseClient = mock(OAuth2AccessTokenResponseClient.class);
		this.authenticationProvider = new OAuth2AuthorizationCodeAuthenticationProvider(this.accessTokenResponseClient);

		when(this.authorizationRequest.getState()).thenReturn("12345");
		when(this.authorizationResponse.getState()).thenReturn("12345");
		when(this.authorizationRequest.getRedirectUri()).thenReturn("https://example.com");
		when(this.authorizationResponse.getRedirectUri()).thenReturn("https://example.com");
	}

	@Test
	public void constructorWhenAccessTokenResponseClientIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationCodeAuthenticationProvider(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void supportsWhenTypeOAuth2AuthorizationCodeAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2AuthorizationCodeAuthenticationToken.class)).isTrue();
	}

	@Test
	public void authenticateWhenAuthorizationErrorResponseThenThrowOAuth2AuthorizationException() {
		when(this.authorizationResponse.statusError()).thenReturn(true);
		when(this.authorizationResponse.getError()).thenReturn(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST));

		assertThatThrownBy(() -> {
			this.authenticationProvider.authenticate(
					new OAuth2AuthorizationCodeAuthenticationToken(
							this.clientRegistration, this.authorizationExchange));
		}).isInstanceOf(OAuth2AuthorizationException.class).hasMessageContaining(OAuth2ErrorCodes.INVALID_REQUEST);
	}

	@Test
	public void authenticateWhenAuthorizationResponseStateNotEqualAuthorizationRequestStateThenThrowOAuth2AuthorizationException() {
		when(this.authorizationRequest.getState()).thenReturn("12345");
		when(this.authorizationResponse.getState()).thenReturn("67890");

		assertThatThrownBy(() -> {
			this.authenticationProvider.authenticate(
					new OAuth2AuthorizationCodeAuthenticationToken(
							this.clientRegistration, this.authorizationExchange));
		}).isInstanceOf(OAuth2AuthorizationException.class).hasMessageContaining("invalid_state_parameter");
	}

	@Test
	public void authenticateWhenAuthorizationResponseRedirectUriNotEqualAuthorizationRequestRedirectUriThenThrowOAuth2AuthorizationException() {
		when(this.authorizationRequest.getRedirectUri()).thenReturn("https://example.com");
		when(this.authorizationResponse.getRedirectUri()).thenReturn("https://example2.com");

		assertThatThrownBy(() -> {
			this.authenticationProvider.authenticate(
					new OAuth2AuthorizationCodeAuthenticationToken(
							this.clientRegistration, this.authorizationExchange));
		}).isInstanceOf(OAuth2AuthorizationException.class).hasMessageContaining("invalid_redirect_uri_parameter");
	}

	@Test
	public void authenticateWhenAuthorizationSuccessResponseThenExchangedForAccessToken() {
		OAuth2AccessToken accessToken = mock(OAuth2AccessToken.class);
		OAuth2RefreshToken refreshToken = mock(OAuth2RefreshToken.class);
		OAuth2AccessTokenResponse accessTokenResponse = mock(OAuth2AccessTokenResponse.class);
		when(accessTokenResponse.getAccessToken()).thenReturn(accessToken);
		when(accessTokenResponse.getRefreshToken()).thenReturn(refreshToken);
		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(accessTokenResponse);

		OAuth2AuthorizationCodeAuthenticationToken authenticationResult =
			(OAuth2AuthorizationCodeAuthenticationToken) this.authenticationProvider.authenticate(
				new OAuth2AuthorizationCodeAuthenticationToken(this.clientRegistration, this.authorizationExchange));

		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.getPrincipal()).isEqualTo(this.clientRegistration.getClientId());
		assertThat(authenticationResult.getCredentials()).isEqualTo(accessToken.getTokenValue());
		assertThat(authenticationResult.getAuthorities()).isEqualTo(Collections.emptyList());
		assertThat(authenticationResult.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authenticationResult.getAuthorizationExchange()).isEqualTo(this.authorizationExchange);
		assertThat(authenticationResult.getAccessToken()).isEqualTo(accessToken);
		assertThat(authenticationResult.getRefreshToken()).isEqualTo(refreshToken);
	}
}
