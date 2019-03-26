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
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link OAuth2LoginAuthenticationProvider}.
 *
 * @author Joe Grandja
 */
@PrepareForTest({ClientRegistration.class, OAuth2AuthorizationRequest.class,
	OAuth2AuthorizationResponse.class, OAuth2AccessTokenResponse.class})
@RunWith(PowerMockRunner.class)
public class OAuth2LoginAuthenticationProviderTests {
	private ClientRegistration clientRegistration;
	private OAuth2AuthorizationRequest authorizationRequest;
	private OAuth2AuthorizationResponse authorizationResponse;
	private OAuth2AuthorizationExchange authorizationExchange;
	private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;
	private OAuth2UserService<OAuth2UserRequest, OAuth2User> userService;
	private OAuth2LoginAuthenticationProvider authenticationProvider;

	@Rule
	public ExpectedException exception = ExpectedException.none();

	@Before
	@SuppressWarnings("unchecked")
	public void setUp() throws Exception {
		this.clientRegistration = mock(ClientRegistration.class);
		this.authorizationRequest = mock(OAuth2AuthorizationRequest.class);
		this.authorizationResponse = mock(OAuth2AuthorizationResponse.class);
		this.authorizationExchange = new OAuth2AuthorizationExchange(this.authorizationRequest, this.authorizationResponse);
		this.accessTokenResponseClient = mock(OAuth2AccessTokenResponseClient.class);
		this.userService = mock(OAuth2UserService.class);
		this.authenticationProvider = new OAuth2LoginAuthenticationProvider(this.accessTokenResponseClient, this.userService);

		when(this.authorizationRequest.getScopes()).thenReturn(new LinkedHashSet<>(Arrays.asList("scope1", "scope2")));
		when(this.authorizationRequest.getState()).thenReturn("12345");
		when(this.authorizationResponse.getState()).thenReturn("12345");
		when(this.authorizationRequest.getRedirectUri()).thenReturn("https://example.com");
		when(this.authorizationResponse.getRedirectUri()).thenReturn("https://example.com");
	}

	@Test
	public void constructorWhenAccessTokenResponseClientIsNullThenThrowIllegalArgumentException() {
		this.exception.expect(IllegalArgumentException.class);
		new OAuth2LoginAuthenticationProvider(null, this.userService);
	}

	@Test
	public void constructorWhenUserServiceIsNullThenThrowIllegalArgumentException() {
		this.exception.expect(IllegalArgumentException.class);
		new OAuth2LoginAuthenticationProvider(this.accessTokenResponseClient, null);
	}

	@Test
	public void setAuthoritiesMapperWhenAuthoritiesMapperIsNullThenThrowIllegalArgumentException() {
		this.exception.expect(IllegalArgumentException.class);
		this.authenticationProvider.setAuthoritiesMapper(null);
	}

	@Test
	public void supportsWhenTypeOAuth2LoginAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2LoginAuthenticationToken.class)).isTrue();
	}

	@Test
	public void authenticateWhenAuthorizationRequestContainsOpenidScopeThenReturnNull() {
		when(this.authorizationRequest.getScopes()).thenReturn(new LinkedHashSet<>(Collections.singleton("openid")));

		OAuth2LoginAuthenticationToken authentication =
			(OAuth2LoginAuthenticationToken) this.authenticationProvider.authenticate(
				new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));

		assertThat(authentication).isNull();
	}

	@Test
	public void authenticateWhenAuthorizationErrorResponseThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString(OAuth2ErrorCodes.INVALID_REQUEST));

		when(this.authorizationResponse.statusError()).thenReturn(true);
		when(this.authorizationResponse.getError()).thenReturn(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST));

		this.authenticationProvider.authenticate(
			new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));
	}

	@Test
	public void authenticateWhenAuthorizationResponseStateNotEqualAuthorizationRequestStateThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("invalid_state_parameter"));

		when(this.authorizationRequest.getState()).thenReturn("12345");
		when(this.authorizationResponse.getState()).thenReturn("67890");

		this.authenticationProvider.authenticate(
			new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));
	}

	@Test
	public void authenticateWhenAuthorizationResponseRedirectUriNotEqualAuthorizationRequestRedirectUriThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("invalid_redirect_uri_parameter"));

		when(this.authorizationRequest.getRedirectUri()).thenReturn("https://example.com");
		when(this.authorizationResponse.getRedirectUri()).thenReturn("https://example2.com");

		this.authenticationProvider.authenticate(
			new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));
	}

	@Test
	public void authenticateWhenLoginSuccessThenReturnAuthentication() {
		OAuth2AccessTokenResponse accessTokenResponse = this.accessTokenSuccessResponse();
		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(accessTokenResponse);

		OAuth2User principal = mock(OAuth2User.class);
		List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
		when(principal.getAuthorities()).thenAnswer(
			(Answer<List<GrantedAuthority>>) invocation -> authorities);
		when(this.userService.loadUser(any())).thenReturn(principal);

		OAuth2LoginAuthenticationToken authentication =
			(OAuth2LoginAuthenticationToken) this.authenticationProvider.authenticate(
				new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));

		assertThat(authentication.isAuthenticated()).isTrue();
		assertThat(authentication.getPrincipal()).isEqualTo(principal);
		assertThat(authentication.getCredentials()).isEqualTo("");
		assertThat(authentication.getAuthorities()).isEqualTo(authorities);
		assertThat(authentication.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authentication.getAuthorizationExchange()).isEqualTo(this.authorizationExchange);
		assertThat(authentication.getAccessToken()).isEqualTo(accessTokenResponse.getAccessToken());
		assertThat(authentication.getRefreshToken()).isEqualTo(accessTokenResponse.getRefreshToken());
	}

	@Test
	public void authenticateWhenAuthoritiesMapperSetThenReturnMappedAuthorities() {
		OAuth2AccessTokenResponse accessTokenResponse = this.accessTokenSuccessResponse();
		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(accessTokenResponse);

		OAuth2User principal = mock(OAuth2User.class);
		List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
		when(principal.getAuthorities()).thenAnswer(
			(Answer<List<GrantedAuthority>>) invocation -> authorities);
		when(this.userService.loadUser(any())).thenReturn(principal);

		List<GrantedAuthority> mappedAuthorities = AuthorityUtils.createAuthorityList("ROLE_OAUTH2_USER");
		GrantedAuthoritiesMapper authoritiesMapper = mock(GrantedAuthoritiesMapper.class);
		when(authoritiesMapper.mapAuthorities(anyCollection())).thenAnswer(
			(Answer<List<GrantedAuthority>>) invocation -> mappedAuthorities);
		this.authenticationProvider.setAuthoritiesMapper(authoritiesMapper);

		OAuth2LoginAuthenticationToken authentication =
			(OAuth2LoginAuthenticationToken) this.authenticationProvider.authenticate(
				new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));

		assertThat(authentication.getAuthorities()).isEqualTo(mappedAuthorities);
	}

	// gh-5368
	@Test
	public void authenticateWhenTokenSuccessResponseThenAdditionalParametersAddedToUserRequest() {
		OAuth2AccessTokenResponse accessTokenResponse = this.accessTokenSuccessResponse();
		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(accessTokenResponse);

		OAuth2User principal = mock(OAuth2User.class);
		List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
		when(principal.getAuthorities()).thenAnswer(
				(Answer<List<GrantedAuthority>>) invocation -> authorities);
		ArgumentCaptor<OAuth2UserRequest> userRequestArgCaptor = ArgumentCaptor.forClass(OAuth2UserRequest.class);
		when(this.userService.loadUser(userRequestArgCaptor.capture())).thenReturn(principal);

		this.authenticationProvider.authenticate(
				new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));

		assertThat(userRequestArgCaptor.getValue().getAdditionalParameters()).containsAllEntriesOf(
				accessTokenResponse.getAdditionalParameters());
	}

	private OAuth2AccessTokenResponse accessTokenSuccessResponse() {
		Instant expiresAt = Instant.now().plusSeconds(5);
		Set<String> scopes = new LinkedHashSet<>(Arrays.asList("scope1", "scope2"));
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put("param1", "value1");
		additionalParameters.put("param2", "value2");

		return OAuth2AccessTokenResponse
				.withToken("access-token-1234")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.expiresIn(expiresAt.getEpochSecond())
				.scopes(scopes)
				.refreshToken("refresh-token-1234")
				.additionalParameters(additionalParameters)
				.build();

	}
}
