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
package org.springframework.security.oauth2.client.oidc.authentication;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.stubbing.Answer;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

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
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link OidcAuthorizationCodeAuthenticationProvider}.
 *
 * @author Joe Grandja
 */
@PrepareForTest({ClientRegistration.class, OAuth2AuthorizationRequest.class, OAuth2AuthorizationResponse.class,
	OAuth2AccessTokenResponse.class, OidcAuthorizationCodeAuthenticationProvider.class})
@RunWith(PowerMockRunner.class)
public class OidcAuthorizationCodeAuthenticationProviderTests {
	private ClientRegistration clientRegistration;
	private ClientRegistration.ProviderDetails providerDetails;
	private OAuth2AuthorizationRequest authorizationRequest;
	private OAuth2AuthorizationResponse authorizationResponse;
	private OAuth2AuthorizationExchange authorizationExchange;
	private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;
	private OAuth2AccessTokenResponse accessTokenResponse;
	private OAuth2UserService<OidcUserRequest, OidcUser> userService;
	private OidcAuthorizationCodeAuthenticationProvider authenticationProvider;

	@Rule
	public ExpectedException exception = ExpectedException.none();

	@Before
	@SuppressWarnings("unchecked")
	public void setUp() throws Exception {
		this.clientRegistration = mock(ClientRegistration.class);
		this.providerDetails = mock(ClientRegistration.ProviderDetails.class);
		this.authorizationRequest = mock(OAuth2AuthorizationRequest.class);
		this.authorizationResponse = mock(OAuth2AuthorizationResponse.class);
		this.authorizationExchange = new OAuth2AuthorizationExchange(this.authorizationRequest, this.authorizationResponse);
		this.accessTokenResponseClient = mock(OAuth2AccessTokenResponseClient.class);
		this.accessTokenResponse = this.accessTokenSuccessResponse();
		this.userService = mock(OAuth2UserService.class);
		this.authenticationProvider = PowerMockito.spy(
			new OidcAuthorizationCodeAuthenticationProvider(this.accessTokenResponseClient, this.userService));

		when(this.clientRegistration.getRegistrationId()).thenReturn("client-registration-id-1");
		when(this.clientRegistration.getClientId()).thenReturn("client1");
		when(this.clientRegistration.getProviderDetails()).thenReturn(this.providerDetails);
		when(this.providerDetails.getJwkSetUri()).thenReturn("https://provider.com/oauth2/keys");
		when(this.authorizationRequest.getScopes()).thenReturn(new LinkedHashSet<>(Arrays.asList("openid", "profile", "email")));
		when(this.authorizationRequest.getState()).thenReturn("12345");
		when(this.authorizationResponse.getState()).thenReturn("12345");
		when(this.authorizationRequest.getRedirectUri()).thenReturn("https://example.com");
		when(this.authorizationResponse.getRedirectUri()).thenReturn("https://example.com");
		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(this.accessTokenResponse);
	}

	@Test
	public void constructorWhenAccessTokenResponseClientIsNullThenThrowIllegalArgumentException() {
		this.exception.expect(IllegalArgumentException.class);
		new OidcAuthorizationCodeAuthenticationProvider(null, this.userService);
	}

	@Test
	public void constructorWhenUserServiceIsNullThenThrowIllegalArgumentException() {
		this.exception.expect(IllegalArgumentException.class);
		new OidcAuthorizationCodeAuthenticationProvider(this.accessTokenResponseClient, null);
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
	public void authenticateWhenAuthorizationRequestDoesNotContainOpenidScopeThenReturnNull() {
		when(this.authorizationRequest.getScopes()).thenReturn(new LinkedHashSet<>(Collections.singleton("scope1")));

		OAuth2LoginAuthenticationToken authentication =
			(OAuth2LoginAuthenticationToken) this.authenticationProvider.authenticate(
				new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));

		assertThat(authentication).isNull();
	}

	@Test
	public void authenticateWhenAuthorizationErrorResponseThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString(OAuth2ErrorCodes.INVALID_SCOPE));

		when(this.authorizationResponse.statusError()).thenReturn(true);
		when(this.authorizationResponse.getError()).thenReturn(new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE));

		this.authenticationProvider.authenticate(
			new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));
	}

	@Test
	public void authenticateWhenAuthorizationResponseStateNotEqualAuthorizationRequestStateThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("invalid_state_parameter"));

		when(this.authorizationRequest.getState()).thenReturn("34567");
		when(this.authorizationResponse.getState()).thenReturn("89012");

		this.authenticationProvider.authenticate(
			new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));
	}

	@Test
	public void authenticateWhenTokenResponseDoesNotContainIdTokenThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("invalid_id_token"));

		OAuth2AccessTokenResponse accessTokenResponse =
				OAuth2AccessTokenResponse.withResponse(this.accessTokenSuccessResponse())
						.additionalParameters(Collections.emptyMap())
						.build();
		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(accessTokenResponse);

		this.authenticationProvider.authenticate(
			new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));
	}

	@Test
	public void authenticateWhenJwkSetUriNotSetThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("missing_signature_verifier"));

		when(this.providerDetails.getJwkSetUri()).thenReturn(null);

		this.authenticationProvider.authenticate(
			new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));
	}

	@Test
	public void authenticateWhenIdTokenIssuerClaimIsNullThenThrowOAuth2AuthenticationException() throws Exception {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("invalid_id_token"));

		Map<String, Object> claims = new HashMap<>();
		claims.put(IdTokenClaimNames.SUB, "subject1");

		this.setUpIdToken(claims);

		this.authenticationProvider.authenticate(
			new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));
	}

	@Test
	public void authenticateWhenIdTokenSubjectClaimIsNullThenThrowOAuth2AuthenticationException() throws Exception {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("invalid_id_token"));

		Map<String, Object> claims = new HashMap<>();
		claims.put(IdTokenClaimNames.ISS, "https://provider.com");

		this.setUpIdToken(claims);

		this.authenticationProvider.authenticate(
			new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));
	}

	@Test
	public void authenticateWhenIdTokenAudienceClaimIsNullThenThrowOAuth2AuthenticationException() throws Exception {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("invalid_id_token"));

		Map<String, Object> claims = new HashMap<>();
		claims.put(IdTokenClaimNames.ISS, "https://provider.com");
		claims.put(IdTokenClaimNames.SUB, "subject1");

		this.setUpIdToken(claims);

		this.authenticationProvider.authenticate(
			new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));
	}

	@Test
	public void authenticateWhenIdTokenAudienceClaimDoesNotContainClientIdThenThrowOAuth2AuthenticationException() throws Exception {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("invalid_id_token"));

		Map<String, Object> claims = new HashMap<>();
		claims.put(IdTokenClaimNames.ISS, "https://provider.com");
		claims.put(IdTokenClaimNames.SUB, "subject1");
		claims.put(IdTokenClaimNames.AUD, Collections.singletonList("other-client"));

		this.setUpIdToken(claims);

		this.authenticationProvider.authenticate(
			new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));
	}

	@Test
	public void authenticateWhenIdTokenMultipleAudienceClaimAndAuthorizedPartyClaimIsNullThenThrowOAuth2AuthenticationException() throws Exception {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("invalid_id_token"));

		Map<String, Object> claims = new HashMap<>();
		claims.put(IdTokenClaimNames.ISS, "https://provider.com");
		claims.put(IdTokenClaimNames.SUB, "subject1");
		claims.put(IdTokenClaimNames.AUD, Arrays.asList("client1", "client2"));

		this.setUpIdToken(claims);

		this.authenticationProvider.authenticate(
			new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));
	}

	@Test
	public void authenticateWhenIdTokenAuthorizedPartyClaimNotEqualToClientIdThenThrowOAuth2AuthenticationException() throws Exception {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("invalid_id_token"));

		Map<String, Object> claims = new HashMap<>();
		claims.put(IdTokenClaimNames.ISS, "https://provider.com");
		claims.put(IdTokenClaimNames.SUB, "subject1");
		claims.put(IdTokenClaimNames.AUD, Arrays.asList("client1", "client2"));
		claims.put(IdTokenClaimNames.AZP, "other-client");

		this.setUpIdToken(claims);

		this.authenticationProvider.authenticate(
			new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));
	}

	@Test
	public void authenticateWhenIdTokenExpiresAtIsBeforeNowThenThrowOAuth2AuthenticationException() throws Exception {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("invalid_id_token"));

		Map<String, Object> claims = new HashMap<>();
		claims.put(IdTokenClaimNames.ISS, "https://provider.com");
		claims.put(IdTokenClaimNames.SUB, "subject1");
		claims.put(IdTokenClaimNames.AUD, Arrays.asList("client1", "client2"));
		claims.put(IdTokenClaimNames.AZP, "client1");

		Instant issuedAt = Instant.now().minusSeconds(10);
		Instant expiresAt = Instant.from(issuedAt).plusSeconds(5);

		this.setUpIdToken(claims, issuedAt, expiresAt);

		this.authenticationProvider.authenticate(
			new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));
	}

	@Test
	public void authenticateWhenIdTokenIssuedAtIsAfterMaxIssuedAtThenThrowOAuth2AuthenticationException() throws Exception {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("invalid_id_token"));

		Map<String, Object> claims = new HashMap<>();
		claims.put(IdTokenClaimNames.ISS, "https://provider.com");
		claims.put(IdTokenClaimNames.SUB, "subject1");
		claims.put(IdTokenClaimNames.AUD, Arrays.asList("client1", "client2"));
		claims.put(IdTokenClaimNames.AZP, "client1");

		Instant issuedAt = Instant.now().plusSeconds(35);
		Instant expiresAt = Instant.from(issuedAt).plusSeconds(60);

		this.setUpIdToken(claims, issuedAt, expiresAt);

		this.authenticationProvider.authenticate(
			new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));
	}

	@Test
	public void authenticateWhenLoginSuccessThenReturnAuthentication() throws Exception {
		Map<String, Object> claims = new HashMap<>();
		claims.put(IdTokenClaimNames.ISS, "https://provider.com");
		claims.put(IdTokenClaimNames.SUB, "subject1");
		claims.put(IdTokenClaimNames.AUD, Arrays.asList("client1", "client2"));
		claims.put(IdTokenClaimNames.AZP, "client1");
		this.setUpIdToken(claims);

		OidcUser principal = mock(OidcUser.class);
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
		assertThat(authentication.getAccessToken()).isEqualTo(this.accessTokenResponse.getAccessToken());
		assertThat(authentication.getRefreshToken()).isEqualTo(this.accessTokenResponse.getRefreshToken());
	}

	@Test
	public void authenticateWhenAuthoritiesMapperSetThenReturnMappedAuthorities() throws Exception {
		Map<String, Object> claims = new HashMap<>();
		claims.put(IdTokenClaimNames.ISS, "https://provider.com");
		claims.put(IdTokenClaimNames.SUB, "subject1");
		claims.put(IdTokenClaimNames.AUD, Arrays.asList("client1", "client2"));
		claims.put(IdTokenClaimNames.AZP, "client1");
		this.setUpIdToken(claims);

		OidcUser principal = mock(OidcUser.class);
		List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
		when(principal.getAuthorities()).thenAnswer(
			(Answer<List<GrantedAuthority>>) invocation -> authorities);
		when(this.userService.loadUser(any())).thenReturn(principal);

		List<GrantedAuthority> mappedAuthorities = AuthorityUtils.createAuthorityList("ROLE_OIDC_USER");
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
	public void authenticateWhenTokenSuccessResponseThenAdditionalParametersAddedToUserRequest() throws Exception {
		Map<String, Object> claims = new HashMap<>();
		claims.put(IdTokenClaimNames.ISS, "https://provider.com");
		claims.put(IdTokenClaimNames.SUB, "subject1");
		claims.put(IdTokenClaimNames.AUD, Arrays.asList("client1", "client2"));
		claims.put(IdTokenClaimNames.AZP, "client1");
		this.setUpIdToken(claims);

		OidcUser principal = mock(OidcUser.class);
		List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
		when(principal.getAuthorities()).thenAnswer(
				(Answer<List<GrantedAuthority>>) invocation -> authorities);
		ArgumentCaptor<OidcUserRequest> userRequestArgCaptor = ArgumentCaptor.forClass(OidcUserRequest.class);
		when(this.userService.loadUser(userRequestArgCaptor.capture())).thenReturn(principal);

		this.authenticationProvider.authenticate(new OAuth2LoginAuthenticationToken(
				this.clientRegistration, this.authorizationExchange));

		assertThat(userRequestArgCaptor.getValue().getAdditionalParameters()).containsAllEntriesOf(
				this.accessTokenResponse.getAdditionalParameters());
	}

	private void setUpIdToken(Map<String, Object> claims) throws Exception {
		Instant issuedAt = Instant.now();
		Instant expiresAt = Instant.from(issuedAt).plusSeconds(3600);
		this.setUpIdToken(claims, issuedAt, expiresAt);
	}

	private void setUpIdToken(Map<String, Object> claims, Instant issuedAt, Instant expiresAt) throws Exception {
		Map<String, Object> headers = new HashMap<>();
		headers.put("alg", "RS256");

		Jwt idToken = new Jwt("id-token", issuedAt, expiresAt, headers, claims);

		JwtDecoder jwtDecoder = mock(JwtDecoder.class);
		when(jwtDecoder.decode(anyString())).thenReturn(idToken);
		PowerMockito.doReturn(jwtDecoder).when(this.authenticationProvider, "getJwtDecoder", any(ClientRegistration.class));
	}

	private OAuth2AccessTokenResponse accessTokenSuccessResponse() {
		Instant expiresAt = Instant.now().plusSeconds(5);
		Set<String> scopes = new LinkedHashSet<>(Arrays.asList("openid", "profile", "email"));
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put("param1", "value1");
		additionalParameters.put("param2", "value2");
		additionalParameters.put(OidcParameterNames.ID_TOKEN, "id-token");

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
