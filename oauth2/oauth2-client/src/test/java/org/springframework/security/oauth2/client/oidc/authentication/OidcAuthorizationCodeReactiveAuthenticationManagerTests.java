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
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import reactor.core.publisher.Mono;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.TestOidcIdTokens;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeReactiveAuthenticationManager.createHash;
import static org.springframework.security.oauth2.jwt.TestJwts.jwt;

/**
 * @author Rob Winch
 * @author Joe Grandja
 * @since 5.1
 */
@RunWith(MockitoJUnitRunner.class)
public class OidcAuthorizationCodeReactiveAuthenticationManagerTests {
	@Mock
	private ReactiveOAuth2UserService<OidcUserRequest, OidcUser> userService;

	@Mock
	private ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;

	@Mock
	private ReactiveJwtDecoder jwtDecoder;

	private ClientRegistration.Builder registration = TestClientRegistrations.clientRegistration()
			.scope("openid");

	private OAuth2AuthorizationResponse.Builder authorizationResponseBldr = OAuth2AuthorizationResponse
			.success("code")
			.state("state");

	private OidcIdToken idToken = TestOidcIdTokens.idToken().build();

	private OidcAuthorizationCodeReactiveAuthenticationManager manager;

	private StringKeyGenerator secureKeyGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

	private String nonceHash;

	@Before
	public void setup() {
		this.manager = new OidcAuthorizationCodeReactiveAuthenticationManager(this.accessTokenResponseClient, this.userService);
	}

	@Test
	public void constructorWhenNullAccessTokenResponseClientThenIllegalArgumentException() {
		this.accessTokenResponseClient = null;
		assertThatThrownBy(() -> new OidcAuthorizationCodeReactiveAuthenticationManager(this.accessTokenResponseClient, this.userService))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenNullUserServiceThenIllegalArgumentException() {
		this.userService = null;
		assertThatThrownBy(() -> new OidcAuthorizationCodeReactiveAuthenticationManager(this.accessTokenResponseClient, this.userService))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void setJwtDecoderFactoryWhenNullThenIllegalArgumentException() {
		assertThatThrownBy(() -> this.manager.setJwtDecoderFactory(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void setAuthoritiesMapperWhenAuthoritiesMapperIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.manager.setAuthoritiesMapper(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void authenticateWhenNoSubscriptionThenDoesNothing() {
		// we didn't do anything because it should cause a ClassCastException (as verified below)
		TestingAuthenticationToken token = new TestingAuthenticationToken("a", "b");

		assertThatCode(()-> this.manager.authenticate(token))
				.doesNotThrowAnyException();

		assertThatThrownBy(() -> this.manager.authenticate(token).block())
				.isInstanceOf(Throwable.class);
	}

	@Test
	public void authenticationWhenNotOidcThenEmpty() {
		this.registration.scope("notopenid");
		assertThat(this.manager.authenticate(loginToken()).block()).isNull();
	}

	@Test
	public void authenticationWhenErrorThenOAuth2AuthenticationException() {
		this.authorizationResponseBldr = OAuth2AuthorizationResponse
				.error("error")
				.state("state");
		assertThatThrownBy(() -> this.manager.authenticate(loginToken()).block())
				.isInstanceOf(OAuth2AuthenticationException.class);
	}

	@Test
	public void authenticationWhenStateDoesNotMatchThenOAuth2AuthenticationException() {
		this.authorizationResponseBldr.state("notmatch");
		assertThatThrownBy(() -> this.manager.authenticate(loginToken()).block())
				.isInstanceOf(OAuth2AuthenticationException.class);
	}

	@Test
	public void authenticateWhenIdTokenValidationErrorThenOAuth2AuthenticationException() {
		OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse.withToken("foo")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.additionalParameters(Collections.singletonMap(OidcParameterNames.ID_TOKEN, this.idToken.getTokenValue()))
				.build();
		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(Mono.just(accessTokenResponse));

		when(this.jwtDecoder.decode(any())).thenThrow(new JwtException("ID Token Validation Error"));
		this.manager.setJwtDecoderFactory(c -> this.jwtDecoder);

		assertThatThrownBy(() -> this.manager.authenticate(loginToken()).block())
				.isInstanceOf(OAuth2AuthenticationException.class)
				.hasMessageContaining("[invalid_id_token] ID Token Validation Error");
	}

	@Test
	public void authenticateWhenIdTokenInvalidNonceThenOAuth2AuthenticationException() {
		OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse.withToken("foo")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.additionalParameters(Collections.singletonMap(OidcParameterNames.ID_TOKEN, this.idToken.getTokenValue()))
				.build();

		OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication = loginToken();

		Map<String, Object> claims = new HashMap<>();
		claims.put(IdTokenClaimNames.ISS, "https://issuer.example.com");
		claims.put(IdTokenClaimNames.SUB, "sub");
		claims.put(IdTokenClaimNames.AUD, Arrays.asList("client-id"));
		claims.put(IdTokenClaimNames.NONCE, "invalid-nonce-hash");
		Jwt idToken = jwt().claims(c -> c.putAll(claims)).build();

		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(Mono.just(accessTokenResponse));
		when(this.jwtDecoder.decode(any())).thenReturn(Mono.just(idToken));
		this.manager.setJwtDecoderFactory(c -> this.jwtDecoder);

		assertThatThrownBy(() -> this.manager.authenticate(authorizationCodeAuthentication).block())
				.isInstanceOf(OAuth2AuthenticationException.class)
				.hasMessageContaining("[invalid_nonce]");
	}

	@Test
	public void authenticationWhenOAuth2UserNotFoundThenEmpty() {
		OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse.withToken("foo")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.additionalParameters(Collections.singletonMap(OidcParameterNames.ID_TOKEN, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."))
				.build();

		OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication = loginToken();

		Map<String, Object> claims = new HashMap<>();
		claims.put(IdTokenClaimNames.ISS, "https://issuer.example.com");
		claims.put(IdTokenClaimNames.SUB, "rob");
		claims.put(IdTokenClaimNames.AUD, Arrays.asList("client-id"));
		claims.put(IdTokenClaimNames.NONCE, this.nonceHash);
		Jwt idToken = jwt().claims(c -> c.putAll(claims)).build();

		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(Mono.just(accessTokenResponse));
		when(this.userService.loadUser(any())).thenReturn(Mono.empty());
		when(this.jwtDecoder.decode(any())).thenReturn(Mono.just(idToken));
		this.manager.setJwtDecoderFactory(c -> this.jwtDecoder);
		assertThat(this.manager.authenticate(authorizationCodeAuthentication).block()).isNull();
	}

	@Test
	public void authenticationWhenOAuth2UserFoundThenSuccess() {
		OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse.withToken("foo")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.additionalParameters(Collections.singletonMap(OidcParameterNames.ID_TOKEN, this.idToken.getTokenValue()))
				.build();

		OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication = loginToken();

		Map<String, Object> claims = new HashMap<>();
		claims.put(IdTokenClaimNames.ISS, "https://issuer.example.com");
		claims.put(IdTokenClaimNames.SUB, "rob");
		claims.put(IdTokenClaimNames.AUD, Arrays.asList("client-id"));
		claims.put(IdTokenClaimNames.NONCE, this.nonceHash);
		Jwt idToken = jwt().claims(c -> c.putAll(claims)).build();

		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(Mono.just(accessTokenResponse));
		DefaultOidcUser user = new DefaultOidcUser(AuthorityUtils.createAuthorityList("ROLE_USER"), this.idToken);
		when(this.userService.loadUser(any())).thenReturn(Mono.just(user));
		when(this.jwtDecoder.decode(any())).thenReturn(Mono.just(idToken));
		this.manager.setJwtDecoderFactory(c -> this.jwtDecoder);

		OAuth2LoginAuthenticationToken result = (OAuth2LoginAuthenticationToken) this.manager.authenticate(authorizationCodeAuthentication).block();

		assertThat(result.getPrincipal()).isEqualTo(user);
		assertThat(result.getAuthorities()).containsOnlyElementsOf(user.getAuthorities());
		assertThat(result.isAuthenticated()).isTrue();
	}

	@Test
	public void authenticationWhenRefreshTokenThenRefreshTokenInAuthorizedClient() {
		OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse.withToken("foo")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.additionalParameters(Collections.singletonMap(OidcParameterNames.ID_TOKEN, this.idToken.getTokenValue()))
				.refreshToken("refresh-token")
				.build();

		OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication = loginToken();

		Map<String, Object> claims = new HashMap<>();
		claims.put(IdTokenClaimNames.ISS, "https://issuer.example.com");
		claims.put(IdTokenClaimNames.SUB, "rob");
		claims.put(IdTokenClaimNames.AUD, Arrays.asList("client-id"));
		claims.put(IdTokenClaimNames.NONCE, this.nonceHash);
		Jwt idToken = jwt().claims(c -> c.putAll(claims)).build();

		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(Mono.just(accessTokenResponse));
		DefaultOidcUser user = new DefaultOidcUser(AuthorityUtils.createAuthorityList("ROLE_USER"), this.idToken);
		when(this.userService.loadUser(any())).thenReturn(Mono.just(user));
		when(this.jwtDecoder.decode(any())).thenReturn(Mono.just(idToken));
		this.manager.setJwtDecoderFactory(c -> this.jwtDecoder);

		OAuth2LoginAuthenticationToken result = (OAuth2LoginAuthenticationToken) this.manager.authenticate(authorizationCodeAuthentication).block();

		assertThat(result.getPrincipal()).isEqualTo(user);
		assertThat(result.getAuthorities()).containsOnlyElementsOf(user.getAuthorities());
		assertThat(result.isAuthenticated()).isTrue();
		assertThat(result.getRefreshToken().getTokenValue()).isNotNull();
	}

	// gh-5368
	@Test
	public void authenticateWhenTokenSuccessResponseThenAdditionalParametersAddedToUserRequest() {
		ClientRegistration clientRegistration = this.registration.build();
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(OidcParameterNames.ID_TOKEN, this.idToken.getTokenValue());
		additionalParameters.put("param1", "value1");
		additionalParameters.put("param2", "value2");
		OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse.withToken("foo")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.additionalParameters(additionalParameters)
				.build();

		OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication = loginToken();

		Map<String, Object> claims = new HashMap<>();
		claims.put(IdTokenClaimNames.ISS, "https://issuer.example.com");
		claims.put(IdTokenClaimNames.SUB, "rob");
		claims.put(IdTokenClaimNames.AUD, Arrays.asList(clientRegistration.getClientId()));
		claims.put(IdTokenClaimNames.NONCE, this.nonceHash);
		Jwt idToken = jwt().claims(c -> c.putAll(claims)).build();

		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(Mono.just(accessTokenResponse));
		DefaultOidcUser user = new DefaultOidcUser(AuthorityUtils.createAuthorityList("ROLE_USER"), this.idToken);
		ArgumentCaptor<OidcUserRequest> userRequestArgCaptor = ArgumentCaptor.forClass(OidcUserRequest.class);
		when(this.userService.loadUser(userRequestArgCaptor.capture())).thenReturn(Mono.just(user));
		when(this.jwtDecoder.decode(any())).thenReturn(Mono.just(idToken));
		this.manager.setJwtDecoderFactory(c -> this.jwtDecoder);

		this.manager.authenticate(authorizationCodeAuthentication).block();

		assertThat(userRequestArgCaptor.getValue().getAdditionalParameters())
				.containsAllEntriesOf(accessTokenResponse.getAdditionalParameters());
	}

	@Test
	public void authenticateWhenAuthoritiesMapperSetThenReturnMappedAuthorities() {
		ClientRegistration clientRegistration = this.registration.build();
		OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse.withToken("foo")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.additionalParameters(Collections.singletonMap(OidcParameterNames.ID_TOKEN, this.idToken.getTokenValue()))
				.build();

		OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication = loginToken();

		Map<String, Object> claims = new HashMap<>();
		claims.put(IdTokenClaimNames.ISS, "https://issuer.example.com");
		claims.put(IdTokenClaimNames.SUB, "rob");
		claims.put(IdTokenClaimNames.AUD, Collections.singletonList(clientRegistration.getClientId()));
		claims.put(IdTokenClaimNames.NONCE, this.nonceHash);
		Jwt idToken = jwt().claims(c -> c.putAll(claims)).build();


		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(Mono.just(accessTokenResponse));
		DefaultOidcUser user = new DefaultOidcUser(AuthorityUtils.createAuthorityList("ROLE_USER"), this.idToken);
		ArgumentCaptor<OidcUserRequest> userRequestArgCaptor = ArgumentCaptor.forClass(OidcUserRequest.class);
		when(this.userService.loadUser(userRequestArgCaptor.capture())).thenReturn(Mono.just(user));

		List<GrantedAuthority> mappedAuthorities = AuthorityUtils.createAuthorityList("ROLE_OIDC_USER");
		GrantedAuthoritiesMapper authoritiesMapper = mock(GrantedAuthoritiesMapper.class);
		when(authoritiesMapper.mapAuthorities(anyCollection())).thenAnswer(
				(Answer<List<GrantedAuthority>>) invocation -> mappedAuthorities);
		when(this.jwtDecoder.decode(any())).thenReturn(Mono.just(idToken));
		this.manager.setJwtDecoderFactory(c -> this.jwtDecoder);
		this.manager.setAuthoritiesMapper(authoritiesMapper);

		Authentication result = this.manager.authenticate(authorizationCodeAuthentication).block();

		assertThat(result.getAuthorities()).isEqualTo(mappedAuthorities);
	}

	private OAuth2AuthorizationCodeAuthenticationToken loginToken() {
		ClientRegistration clientRegistration = this.registration.build();
		Map<String, Object> attributes = new HashMap<>();
		Map<String, Object> additionalParameters = new HashMap<>();
		try {
			String nonce = this.secureKeyGenerator.generateKey();
			this.nonceHash = createHash(nonce);
			attributes.put(OidcParameterNames.NONCE, nonce);
			additionalParameters.put(OidcParameterNames.NONCE, this.nonceHash);
		} catch (NoSuchAlgorithmException e) { }
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest
				.authorizationCode()
				.state("state")
				.clientId(clientRegistration.getClientId())
				.authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
				.redirectUri(clientRegistration.getRedirectUriTemplate())
				.scopes(clientRegistration.getScopes())
				.additionalParameters(additionalParameters)
				.attributes(attributes)
				.build();
		OAuth2AuthorizationResponse authorizationResponse = this.authorizationResponseBldr
				.redirectUri(clientRegistration.getRedirectUriTemplate())
				.build();
		OAuth2AuthorizationExchange authorizationExchange = new OAuth2AuthorizationExchange(authorizationRequest,
				authorizationResponse);
		return new OAuth2AuthorizationCodeAuthenticationToken(clientRegistration, authorizationExchange);
	}
}
