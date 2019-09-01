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
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
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
import org.springframework.security.oauth2.jwt.JwtException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.client.registration.TestClientRegistrations.clientRegistration;
import static org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationRequests.request;
import static org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationResponses.error;
import static org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationResponses.success;

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
	private StringKeyGenerator stringKeyGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);
	private String nonce = this.stringKeyGenerator.generateKey();
	private String nonceHash;

	@Rule
	public ExpectedException exception = ExpectedException.none();

	@Before
	@SuppressWarnings("unchecked")
	public void setUp() {
		try {
			nonceHash = createHash(nonce);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		Map<String, Object> attributes = new HashMap<>();
		Map<String, Object> additionalParameters = new HashMap<>();
		addNonceToRequest(attributes, additionalParameters);

		this.clientRegistration = clientRegistration().clientId("client1").build();
		this.authorizationRequest = request()
				.scope("openid", "profile", "email")
				.attributes(attributes)
				.additionalParameters(additionalParameters)
				.build();
		this.authorizationResponse = success().build();
		this.authorizationExchange = new OAuth2AuthorizationExchange(this.authorizationRequest, this.authorizationResponse);
		this.accessTokenResponseClient = mock(OAuth2AccessTokenResponseClient.class);
		this.accessTokenResponse = this.accessTokenSuccessResponse();
		this.userService = mock(OAuth2UserService.class);
		this.authenticationProvider =
			new OidcAuthorizationCodeAuthenticationProvider(this.accessTokenResponseClient, this.userService);

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
		OAuth2AuthorizationRequest authorizationRequest = request().scope("scope1").build();
		OAuth2AuthorizationExchange authorizationExchange =
				new OAuth2AuthorizationExchange(authorizationRequest, this.authorizationResponse);

		OAuth2LoginAuthenticationToken authentication =
			(OAuth2LoginAuthenticationToken) this.authenticationProvider.authenticate(
				new OAuth2LoginAuthenticationToken(this.clientRegistration, authorizationExchange));

		assertThat(authentication).isNull();
	}

	@Test
	public void authenticateWhenAuthorizationErrorResponseThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString(OAuth2ErrorCodes.INVALID_SCOPE));

		OAuth2AuthorizationResponse authorizationResponse = error().errorCode(OAuth2ErrorCodes.INVALID_SCOPE).build();
		OAuth2AuthorizationExchange authorizationExchange =
				new OAuth2AuthorizationExchange(this.authorizationRequest, authorizationResponse);

		this.authenticationProvider.authenticate(
			new OAuth2LoginAuthenticationToken(this.clientRegistration, authorizationExchange));
	}

	@Test
	public void authenticateWhenAuthorizationResponseStateNotEqualAuthorizationRequestStateThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("invalid_state_parameter"));

		OAuth2AuthorizationResponse authorizationResponse = success().state("89012").build();
		OAuth2AuthorizationExchange authorizationExchange =
				new OAuth2AuthorizationExchange(this.authorizationRequest, authorizationResponse);

		this.authenticationProvider.authenticate(
			new OAuth2LoginAuthenticationToken(this.clientRegistration, authorizationExchange));
	}

	@Test
	public void authenticateWhenAuthorizationResponseRedirectUriNotEqualAuthorizationRequestRedirectUriThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("invalid_redirect_uri_parameter"));

		OAuth2AuthorizationResponse authorizationResponse = success().redirectUri("https://example2.com").build();
		OAuth2AuthorizationExchange authorizationExchange =
				new OAuth2AuthorizationExchange(this.authorizationRequest, authorizationResponse);

		this.authenticationProvider.authenticate(
			new OAuth2LoginAuthenticationToken(this.clientRegistration, authorizationExchange));
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

		ClientRegistration clientRegistration = clientRegistration().jwkSetUri(null).build();

		this.authenticationProvider.authenticate(
			new OAuth2LoginAuthenticationToken(clientRegistration, this.authorizationExchange));
	}

	@Test
	public void authenticateWhenIdTokenValidationErrorThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("[invalid_id_token] ID Token Validation Error"));

		JwtDecoder jwtDecoder = mock(JwtDecoder.class);
		when(jwtDecoder.decode(anyString())).thenThrow(new JwtException("ID Token Validation Error"));
		this.authenticationProvider.setJwtDecoderFactory(registration -> jwtDecoder);

		this.authenticationProvider.authenticate(
				new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange));
	}

	@Test
	public void authenticateWhenLoginSuccessThenReturnAuthentication() {
		Map<String, Object> claims = new HashMap<>();
		claims.put(IdTokenClaimNames.ISS, "https://provider.com");
		claims.put(IdTokenClaimNames.SUB, "subject1");
		claims.put(IdTokenClaimNames.AUD, Arrays.asList("client1", "client2"));
		claims.put(IdTokenClaimNames.AZP, "client1");
		claims.put(IdTokenClaimNames.NONCE, nonceHash);
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
	public void authenticateWhenAuthoritiesMapperSetThenReturnMappedAuthorities() {
		Map<String, Object> claims = new HashMap<>();
		claims.put(IdTokenClaimNames.ISS, "https://provider.com");
		claims.put(IdTokenClaimNames.SUB, "subject1");
		claims.put(IdTokenClaimNames.AUD, Arrays.asList("client1", "client2"));
		claims.put(IdTokenClaimNames.AZP, "client1");
		claims.put(IdTokenClaimNames.NONCE, nonceHash);
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
	public void authenticateWhenTokenSuccessResponseThenAdditionalParametersAddedToUserRequest() {
		Map<String, Object> claims = new HashMap<>();
		claims.put(IdTokenClaimNames.ISS, "https://provider.com");
		claims.put(IdTokenClaimNames.SUB, "subject1");
		claims.put(IdTokenClaimNames.AUD, Arrays.asList("client1", "client2"));
		claims.put(IdTokenClaimNames.AZP, "client1");
		claims.put(IdTokenClaimNames.NONCE, nonceHash);
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

	// gh-4442
	@Test
	public void authenticateWhenTokenSuccessResponseThenAdditionalParametersAddedToUserRequestNoNonce() {
		OAuth2AuthorizationRequest authorizationRequestNoNonce = request()
				.scope("openid", "profile", "email")
				.attributes(new HashMap<>())
				.additionalParameters(new HashMap<>())
				.build();
		OAuth2AuthorizationExchange authorizationExchangeNoNonce = new OAuth2AuthorizationExchange(authorizationRequestNoNonce, this.authorizationResponse);

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
				this.clientRegistration, authorizationExchangeNoNonce));

		assertThat(userRequestArgCaptor.getValue().getAdditionalParameters()).containsAllEntriesOf(
				this.accessTokenResponse.getAdditionalParameters());
	}

	private void setUpIdToken(Map<String, Object> claims) {
		Jwt idToken = Jwt.withTokenValue("token")
				.header("alg", "none")
				.audience(Collections.singletonList("https://audience.example.org"))
				.expiresAt(Instant.MAX)
				.issuedAt(Instant.MIN)
				.issuer("https://issuer.example.org")
				.jti("jti")
				.notBefore(Instant.MIN)
				.subject("mock-test-subject")
				.claims(c -> c.putAll(claims))
				.build();
		JwtDecoder jwtDecoder = mock(JwtDecoder.class);
		when(jwtDecoder.decode(anyString())).thenReturn(idToken);
		this.authenticationProvider.setJwtDecoderFactory(registration -> jwtDecoder);
	}

	private OAuth2AccessTokenResponse accessTokenSuccessResponse() {
		Instant expiresAt = Instant.now().plusSeconds(5);
		Set<String> scopes = new LinkedHashSet<>(Arrays.asList("openid", "profile", "email"));
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put("param1", "value1");
		additionalParameters.put("param2", "value2");
		additionalParameters.put(OidcParameterNames.ID_TOKEN, "id-token");
		additionalParameters.put(IdTokenClaimNames.NONCE, nonceHash);

		return OAuth2AccessTokenResponse
				.withToken("access-token-1234")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.expiresIn(expiresAt.getEpochSecond())
				.scopes(scopes)
				.refreshToken("refresh-token-1234")
				.additionalParameters(additionalParameters)
				.build();

	}

	/**
	 * Adds nonce for use in OpenID Connect Authentication Requests
	 *
	 * @param attributes where {@link IdTokenClaimNames#NONCE} is stored for the token request
	 * @param additionalParameters where the hash of {@link IdTokenClaimNames#NONCE} is added to be used in the authentication request
	 *
	 * @since 5.2
	 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes">15.5.2.  Nonce Implementation Notes</a>
	 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation">3.1.3.7.  ID Token Validation</a>
	 */
	private void addNonceToRequest(Map<String, Object> attributes, Map<String, Object> additionalParameters) {
		attributes.put(IdTokenClaimNames.NONCE, nonce);
		additionalParameters.put(IdTokenClaimNames.NONCE, nonceHash);
	}

	private String createHash(String nonce) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(nonce.getBytes(StandardCharsets.US_ASCII));
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
	}
}
