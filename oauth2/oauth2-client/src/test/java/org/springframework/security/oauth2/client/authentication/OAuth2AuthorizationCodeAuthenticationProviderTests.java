/*
 * Copyright 2002-2020 the original author or authors.
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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AccessTokenResponses;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationRequests;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationResponses;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link OAuth2AuthorizationCodeAuthenticationProvider}.
 *
 * @author Joe Grandja
 */
public class OAuth2AuthorizationCodeAuthenticationProviderTests {

	private ClientRegistration clientRegistration;

	private OAuth2AuthorizationRequest authorizationRequest;

	private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;

	private OAuth2AuthorizationCodeAuthenticationProvider authenticationProvider;

	@Before
	@SuppressWarnings("unchecked")
	public void setUp() {
		this.clientRegistration = TestClientRegistrations.clientRegistration().build();
		this.authorizationRequest = TestOAuth2AuthorizationRequests.request().build();
		this.accessTokenResponseClient = mock(OAuth2AccessTokenResponseClient.class);
		this.authenticationProvider = new OAuth2AuthorizationCodeAuthenticationProvider(this.accessTokenResponseClient);
	}

	@Test
	public void constructorWhenAccessTokenResponseClientIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new OAuth2AuthorizationCodeAuthenticationProvider(null));
	}

	@Test
	public void supportsWhenTypeOAuth2AuthorizationCodeAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2AuthorizationCodeAuthenticationToken.class)).isTrue();
	}

	@Test
	public void authenticateWhenAuthorizationErrorResponseThenThrowOAuth2AuthorizationException() {
		OAuth2AuthorizationResponse authorizationResponse = TestOAuth2AuthorizationResponses.error()
				.errorCode(OAuth2ErrorCodes.INVALID_REQUEST).build();
		OAuth2AuthorizationExchange authorizationExchange = new OAuth2AuthorizationExchange(this.authorizationRequest,
				authorizationResponse);
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(
						new OAuth2AuthorizationCodeAuthenticationToken(this.clientRegistration, authorizationExchange)))
				.withMessageContaining(OAuth2ErrorCodes.INVALID_REQUEST);
	}

	@Test
	public void authenticateWhenAuthorizationResponseStateNotEqualAuthorizationRequestStateThenThrowOAuth2AuthorizationException() {
		OAuth2AuthorizationResponse authorizationResponse = TestOAuth2AuthorizationResponses.success().state("67890")
				.build();
		OAuth2AuthorizationExchange authorizationExchange = new OAuth2AuthorizationExchange(this.authorizationRequest,
				authorizationResponse);
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(
						new OAuth2AuthorizationCodeAuthenticationToken(this.clientRegistration, authorizationExchange)))
				.withMessageContaining("invalid_state_parameter");
	}

	@Test
	public void authenticateWhenAuthorizationSuccessResponseThenExchangedForAccessToken() {
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse()
				.refreshToken("refresh").build();
		given(this.accessTokenResponseClient.getTokenResponse(any())).willReturn(accessTokenResponse);
		OAuth2AuthorizationExchange authorizationExchange = new OAuth2AuthorizationExchange(this.authorizationRequest,
				TestOAuth2AuthorizationResponses.success().build());
		OAuth2AuthorizationCodeAuthenticationToken authenticationResult = (OAuth2AuthorizationCodeAuthenticationToken) this.authenticationProvider
				.authenticate(
						new OAuth2AuthorizationCodeAuthenticationToken(this.clientRegistration, authorizationExchange));
		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.getPrincipal()).isEqualTo(this.clientRegistration.getClientId());
		assertThat(authenticationResult.getCredentials())
				.isEqualTo(accessTokenResponse.getAccessToken().getTokenValue());
		assertThat(authenticationResult.getAuthorities()).isEqualTo(Collections.emptyList());
		assertThat(authenticationResult.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authenticationResult.getAuthorizationExchange()).isEqualTo(authorizationExchange);
		assertThat(authenticationResult.getAccessToken()).isEqualTo(accessTokenResponse.getAccessToken());
		assertThat(authenticationResult.getRefreshToken()).isEqualTo(accessTokenResponse.getRefreshToken());
	}

	// gh-5368
	@Test
	public void authenticateWhenAuthorizationSuccessResponseThenAdditionalParametersIncluded() {
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put("param1", "value1");
		additionalParameters.put("param2", "value2");
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse()
				.additionalParameters(additionalParameters).build();
		given(this.accessTokenResponseClient.getTokenResponse(any())).willReturn(accessTokenResponse);
		OAuth2AuthorizationExchange authorizationExchange = new OAuth2AuthorizationExchange(this.authorizationRequest,
				TestOAuth2AuthorizationResponses.success().build());
		OAuth2AuthorizationCodeAuthenticationToken authentication = (OAuth2AuthorizationCodeAuthenticationToken) this.authenticationProvider
				.authenticate(
						new OAuth2AuthorizationCodeAuthenticationToken(this.clientRegistration, authorizationExchange));
		assertThat(authentication.getAdditionalParameters())
				.containsAllEntriesOf(accessTokenResponse.getAdditionalParameters());
	}

}
