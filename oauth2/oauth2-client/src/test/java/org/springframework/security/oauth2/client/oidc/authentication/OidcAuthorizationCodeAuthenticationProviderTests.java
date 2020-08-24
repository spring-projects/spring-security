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

import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;
import org.mockito.stubbing.Answer;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationRequests;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationResponses;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.TestJwts;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link OidcAuthorizationCodeAuthenticationProvider}.
 *
 * @author Joe Grandja
 * @author Mark Heckler
 */
public class OidcAuthorizationCodeAuthenticationProviderTests {

	private ClientRegistration clientRegistration;

	private OAuth2AuthorizationRequest authorizationRequest;

	private OAuth2AuthorizationResponse authorizationResponse;

	private OAuth2AuthorizationExchange authorizationExchange;

	private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;

	private OAuth2AccessTokenResponse accessTokenResponse;

	private OAuth2UserService<OidcUserRequest, OidcUser> userService;

	private OidcAuthorizationCodeAuthenticationProvider authenticationProvider;

	private StringKeyGenerator secureKeyGenerator = new Base64StringKeyGenerator(
			Base64.getUrlEncoder().withoutPadding(), 96);

	private String nonceHash;

	@Rule
	public ExpectedException exception = ExpectedException.none();

	@Before
	@SuppressWarnings("unchecked")
	public void setUp() {
		this.clientRegistration = TestClientRegistrations.clientRegistration().clientId("client1").build();
		Map<String, Object> attributes = new HashMap<>();
		Map<String, Object> additionalParameters = new HashMap<>();
		try {
			String nonce = this.secureKeyGenerator.generateKey();
			this.nonceHash = OidcAuthorizationCodeAuthenticationProvider.createHash(nonce);
			attributes.put(OidcParameterNames.NONCE, nonce);
			additionalParameters.put(OidcParameterNames.NONCE, this.nonceHash);
		}
		catch (NoSuchAlgorithmException ex) {
		}
		// @formatter:off
		this.authorizationRequest = TestOAuth2AuthorizationRequests.request()
				.scope("openid", "profile", "email")
				.attributes(attributes)
				.additionalParameters(additionalParameters)
				.build();
		this.authorizationResponse = TestOAuth2AuthorizationResponses.success()
				.build();
		// @formatter:on
		this.authorizationExchange = new OAuth2AuthorizationExchange(this.authorizationRequest,
				this.authorizationResponse);
		this.accessTokenResponseClient = mock(OAuth2AccessTokenResponseClient.class);
		this.accessTokenResponse = this.accessTokenSuccessResponse();
		this.userService = mock(OAuth2UserService.class);
		this.authenticationProvider = new OidcAuthorizationCodeAuthenticationProvider(this.accessTokenResponseClient,
				this.userService);
		given(this.accessTokenResponseClient.getTokenResponse(any())).willReturn(this.accessTokenResponse);
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
	public void setJwtDecoderFactoryWhenNullThenThrowIllegalArgumentException() {
		this.exception.expect(IllegalArgumentException.class);
		this.authenticationProvider.setJwtDecoderFactory(null);
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
		// @formatter:off
		OAuth2AuthorizationRequest authorizationRequest = TestOAuth2AuthorizationRequests.request()
				.scope("scope1")
				.build();
		// @formatter:on
		OAuth2AuthorizationExchange authorizationExchange = new OAuth2AuthorizationExchange(authorizationRequest,
				this.authorizationResponse);
		OAuth2LoginAuthenticationToken authentication = (OAuth2LoginAuthenticationToken) this.authenticationProvider
				.authenticate(new OAuth2LoginAuthenticationToken(this.clientRegistration, authorizationExchange));
		assertThat(authentication).isNull();
	}

	@Test
	public void authenticateWhenAuthorizationErrorResponseThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString(OAuth2ErrorCodes.INVALID_SCOPE));
		// @formatter:off
		OAuth2AuthorizationResponse authorizationResponse = TestOAuth2AuthorizationResponses.error()
				.errorCode(OAuth2ErrorCodes.INVALID_SCOPE)
				.build();
		// @formatter:on
		OAuth2AuthorizationExchange authorizationExchange = new OAuth2AuthorizationExchange(this.authorizationRequest,
				authorizationResponse);
		this.authenticationProvider
				.authenticate(new OAuth2LoginAuthenticationToken(this.clientRegistration, authorizationExchange));
	}

	@Test
	public void authenticateWhenAuthorizationResponseStateNotEqualAuthorizationRequestStateThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("invalid_state_parameter"));
		// @formatter:off
		OAuth2AuthorizationResponse authorizationResponse = TestOAuth2AuthorizationResponses.success()
				.state("89012")
				.build();
		// @formatter:on
		OAuth2AuthorizationExchange authorizationExchange = new OAuth2AuthorizationExchange(this.authorizationRequest,
				authorizationResponse);
		this.authenticationProvider
				.authenticate(new OAuth2LoginAuthenticationToken(this.clientRegistration, authorizationExchange));
	}

	@Test
	public void authenticateWhenTokenResponseDoesNotContainIdTokenThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("invalid_id_token"));
		// @formatter:off
		OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse
				.withResponse(this.accessTokenSuccessResponse())
				.additionalParameters(Collections.emptyMap())
				.build();
		// @formatter:on
		given(this.accessTokenResponseClient.getTokenResponse(any())).willReturn(accessTokenResponse);
		this.authenticationProvider
				.authenticate(new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));
	}

	@Test
	public void authenticateWhenJwkSetUriNotSetThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("missing_signature_verifier"));
		// @formatter:off
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration()
				.jwkSetUri(null)
				.build();
		// @formatter:on
		this.authenticationProvider
				.authenticate(new OAuth2LoginAuthenticationToken(clientRegistration, this.authorizationExchange));
	}

	@Test
	public void authenticateWhenIdTokenValidationErrorThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("[invalid_id_token] ID Token Validation Error"));
		JwtDecoder jwtDecoder = mock(JwtDecoder.class);
		given(jwtDecoder.decode(anyString())).willThrow(new JwtException("ID Token Validation Error"));
		this.authenticationProvider.setJwtDecoderFactory((registration) -> jwtDecoder);
		this.authenticationProvider
				.authenticate(new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));
	}

	@Test
	public void authenticateWhenIdTokenInvalidNonceThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("[invalid_nonce]"));
		Map<String, Object> claims = new HashMap<>();
		claims.put(IdTokenClaimNames.ISS, "https://provider.com");
		claims.put(IdTokenClaimNames.SUB, "subject1");
		claims.put(IdTokenClaimNames.AUD, Arrays.asList("client1", "client2"));
		claims.put(IdTokenClaimNames.AZP, "client1");
		claims.put(IdTokenClaimNames.NONCE, "invalid-nonce-hash");
		this.setUpIdToken(claims);
		this.authenticationProvider
				.authenticate(new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));
	}

	@Test
	public void authenticateWhenLoginSuccessThenReturnAuthentication() {
		Map<String, Object> claims = new HashMap<>();
		claims.put(IdTokenClaimNames.ISS, "https://provider.com");
		claims.put(IdTokenClaimNames.SUB, "subject1");
		claims.put(IdTokenClaimNames.AUD, Arrays.asList("client1", "client2"));
		claims.put(IdTokenClaimNames.AZP, "client1");
		claims.put(IdTokenClaimNames.NONCE, this.nonceHash);
		this.setUpIdToken(claims);
		OidcUser principal = mock(OidcUser.class);
		List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
		given(principal.getAuthorities()).willAnswer((Answer<List<GrantedAuthority>>) (invocation) -> authorities);
		given(this.userService.loadUser(any())).willReturn(principal);
		OAuth2LoginAuthenticationToken authentication = (OAuth2LoginAuthenticationToken) this.authenticationProvider
				.authenticate(new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));
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
	public void authenticateWhenAuthoritiesMapperSetThenReturnMappedAuthorities() {
		Map<String, Object> claims = new HashMap<>();
		claims.put(IdTokenClaimNames.ISS, "https://provider.com");
		claims.put(IdTokenClaimNames.SUB, "subject1");
		claims.put(IdTokenClaimNames.AUD, Arrays.asList("client1", "client2"));
		claims.put(IdTokenClaimNames.AZP, "client1");
		claims.put(IdTokenClaimNames.NONCE, this.nonceHash);
		this.setUpIdToken(claims);
		OidcUser principal = mock(OidcUser.class);
		List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
		given(principal.getAuthorities()).willAnswer((Answer<List<GrantedAuthority>>) (invocation) -> authorities);
		given(this.userService.loadUser(any())).willReturn(principal);
		List<GrantedAuthority> mappedAuthorities = AuthorityUtils.createAuthorityList("ROLE_OIDC_USER");
		GrantedAuthoritiesMapper authoritiesMapper = mock(GrantedAuthoritiesMapper.class);
		given(authoritiesMapper.mapAuthorities(anyCollection()))
				.willAnswer((Answer<List<GrantedAuthority>>) (invocation) -> mappedAuthorities);
		this.authenticationProvider.setAuthoritiesMapper(authoritiesMapper);
		OAuth2LoginAuthenticationToken authentication = (OAuth2LoginAuthenticationToken) this.authenticationProvider
				.authenticate(new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));
		assertThat(authentication.getAuthorities()).isEqualTo(mappedAuthorities);
	}

	// gh-5368
	@Test
	public void authenticateWhenTokenSuccessResponseThenAdditionalParametersAddedToUserRequest() {
		Map<String, Object> claims = new HashMap<>();
		claims.put(IdTokenClaimNames.ISS, "https://provider.com");
		claims.put(IdTokenClaimNames.SUB, "subject1");
		claims.put(IdTokenClaimNames.AUD, Arrays.asList("client1", "client2"));
		claims.put(IdTokenClaimNames.AZP, "client1");
		claims.put(IdTokenClaimNames.NONCE, this.nonceHash);
		this.setUpIdToken(claims);
		OidcUser principal = mock(OidcUser.class);
		List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
		given(principal.getAuthorities()).willAnswer((Answer<List<GrantedAuthority>>) (invocation) -> authorities);
		ArgumentCaptor<OidcUserRequest> userRequestArgCaptor = ArgumentCaptor.forClass(OidcUserRequest.class);
		given(this.userService.loadUser(userRequestArgCaptor.capture())).willReturn(principal);
		this.authenticationProvider
				.authenticate(new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));
		assertThat(userRequestArgCaptor.getValue().getAdditionalParameters())
				.containsAllEntriesOf(this.accessTokenResponse.getAdditionalParameters());
	}

	private void setUpIdToken(Map<String, Object> claims) {
		Jwt idToken = TestJwts.jwt().claims((c) -> c.putAll(claims)).build();
		JwtDecoder jwtDecoder = mock(JwtDecoder.class);
		given(jwtDecoder.decode(anyString())).willReturn(idToken);
		this.authenticationProvider.setJwtDecoderFactory((registration) -> jwtDecoder);
	}

	private OAuth2AccessTokenResponse accessTokenSuccessResponse() {
		Instant expiresAt = Instant.now().plusSeconds(5);
		Set<String> scopes = new LinkedHashSet<>(Arrays.asList("openid", "profile", "email"));
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put("param1", "value1");
		additionalParameters.put("param2", "value2");
		additionalParameters.put(OidcParameterNames.ID_TOKEN, "id-token");
		// @formatter:off
		return OAuth2AccessTokenResponse.withToken("access-token-1234")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.expiresIn(expiresAt.getEpochSecond())
				.scopes(scopes)
				.refreshToken("refresh-token-1234")
				.additionalParameters(additionalParameters)
				.build();
		// @formatter:on
	}

}
