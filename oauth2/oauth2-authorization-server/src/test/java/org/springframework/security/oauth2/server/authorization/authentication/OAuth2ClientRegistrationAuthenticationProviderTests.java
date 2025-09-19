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

package org.springframework.security.oauth2.server.authorization.authentication;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.TestJwsHeaders;
import org.springframework.security.oauth2.jwt.TestJwtClaimsSets;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link OAuth2ClientRegistrationAuthenticationProvider}.
 *
 * @author Joe Grandja
 */
public class OAuth2ClientRegistrationAuthenticationProviderTests {

	private RegisteredClientRepository registeredClientRepository;

	private OAuth2AuthorizationService authorizationService;

	private PasswordEncoder passwordEncoder;

	private OAuth2ClientRegistrationAuthenticationProvider authenticationProvider;

	@BeforeEach
	public void setUp() {
		this.registeredClientRepository = mock(RegisteredClientRepository.class);
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.passwordEncoder = spy(new PasswordEncoder() {
			@Override
			public String encode(CharSequence rawPassword) {
				return NoOpPasswordEncoder.getInstance().encode(rawPassword);
			}

			@Override
			public boolean matches(CharSequence rawPassword, String encodedPassword) {
				return NoOpPasswordEncoder.getInstance().matches(rawPassword, encodedPassword);
			}
		});
		this.authenticationProvider = new OAuth2ClientRegistrationAuthenticationProvider(
				this.registeredClientRepository, this.authorizationService);
		this.authenticationProvider.setPasswordEncoder(this.passwordEncoder);
	}

	@Test
	public void constructorWhenRegisteredClientRepositoryNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new OAuth2ClientRegistrationAuthenticationProvider(null, this.authorizationService))
			.withMessage("registeredClientRepository cannot be null");
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new OAuth2ClientRegistrationAuthenticationProvider(this.registeredClientRepository, null))
			.withMessage("authorizationService cannot be null");
	}

	@Test
	public void setRegisteredClientConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.authenticationProvider.setRegisteredClientConverter(null))
			.withMessage("registeredClientConverter cannot be null");
	}

	@Test
	public void setClientRegistrationConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.authenticationProvider.setClientRegistrationConverter(null))
			.withMessage("clientRegistrationConverter cannot be null");
	}

	@Test
	public void setPasswordEncoderWhenNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.authenticationProvider.setPasswordEncoder(null))
			.withMessage("passwordEncoder cannot be null");
	}

	@Test
	public void supportsWhenTypeOAuth2ClientRegistrationAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2ClientRegistrationAuthenticationToken.class)).isTrue();
	}

	@Test
	public void authenticateWhenPrincipalNotOAuth2TokenAuthenticationTokenThenThrowOAuth2AuthenticationException() {
		TestingAuthenticationToken principal = new TestingAuthenticationToken("principal", "credentials");
		OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.builder()
			.redirectUri("https://client.example.com")
			.build();

		OAuth2ClientRegistrationAuthenticationToken authentication = new OAuth2ClientRegistrationAuthenticationToken(
				principal, clientRegistration);

		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.extracting(OAuth2AuthenticationException::getError)
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
	}

	@Test
	public void authenticateWhenPrincipalNotAuthenticatedThenThrowOAuth2AuthenticationException() {
		JwtAuthenticationToken principal = new JwtAuthenticationToken(createJwtClientRegistration());
		OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.builder()
			.redirectUri("https://client.example.com")
			.build();

		OAuth2ClientRegistrationAuthenticationToken authentication = new OAuth2ClientRegistrationAuthenticationToken(
				principal, clientRegistration);

		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.extracting(OAuth2AuthenticationException::getError)
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
	}

	@Test
	public void authenticateWhenAccessTokenNotFoundThenThrowOAuth2AuthenticationException() {
		Jwt jwt = createJwtClientRegistration();
		JwtAuthenticationToken principal = new JwtAuthenticationToken(jwt,
				AuthorityUtils.createAuthorityList("SCOPE_client.create"));
		OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.builder()
			.redirectUri("https://client.example.com")
			.build();

		OAuth2ClientRegistrationAuthenticationToken authentication = new OAuth2ClientRegistrationAuthenticationToken(
				principal, clientRegistration);

		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.extracting(OAuth2AuthenticationException::getError)
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
		verify(this.authorizationService).findByToken(eq(jwt.getTokenValue()), eq(OAuth2TokenType.ACCESS_TOKEN));
	}

	@Test
	public void authenticateWhenAccessTokenNotActiveThenThrowOAuth2AuthenticationException() {
		Jwt jwt = createJwtClientRegistration();
		OAuth2AccessToken jwtAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), jwt.getClaim(OAuth2ParameterNames.SCOPE));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations
			.authorization(registeredClient, jwtAccessToken, jwt.getClaims())
			.invalidate(jwtAccessToken)
			.build();
		given(this.authorizationService.findByToken(eq(jwtAccessToken.getTokenValue()),
				eq(OAuth2TokenType.ACCESS_TOKEN)))
			.willReturn(authorization);

		JwtAuthenticationToken principal = new JwtAuthenticationToken(jwt,
				AuthorityUtils.createAuthorityList("SCOPE_client.create"));
		OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.builder()
			.redirectUri("https://client.example.com")
			.build();

		OAuth2ClientRegistrationAuthenticationToken authentication = new OAuth2ClientRegistrationAuthenticationToken(
				principal, clientRegistration);

		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.extracting(OAuth2AuthenticationException::getError)
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
		verify(this.authorizationService).findByToken(eq(jwtAccessToken.getTokenValue()),
				eq(OAuth2TokenType.ACCESS_TOKEN));
	}

	@Test
	public void authenticateWhenAccessTokenNotAuthorizedThenThrowOAuth2AuthenticationException() {
		Jwt jwt = createJwt(Collections.singleton("unauthorized.scope"));
		OAuth2AccessToken jwtAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), jwt.getClaim(OAuth2ParameterNames.SCOPE));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations
			.authorization(registeredClient, jwtAccessToken, jwt.getClaims())
			.build();
		given(this.authorizationService.findByToken(eq(jwtAccessToken.getTokenValue()),
				eq(OAuth2TokenType.ACCESS_TOKEN)))
			.willReturn(authorization);

		JwtAuthenticationToken principal = new JwtAuthenticationToken(jwt,
				AuthorityUtils.createAuthorityList("SCOPE_unauthorized.scope"));
		OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.builder()
			.redirectUri("https://client.example.com")
			.build();

		OAuth2ClientRegistrationAuthenticationToken authentication = new OAuth2ClientRegistrationAuthenticationToken(
				principal, clientRegistration);

		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.extracting(OAuth2AuthenticationException::getError)
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INSUFFICIENT_SCOPE);
		verify(this.authorizationService).findByToken(eq(jwtAccessToken.getTokenValue()),
				eq(OAuth2TokenType.ACCESS_TOKEN));
	}

	@Test
	public void authenticateWhenAccessTokenContainsRequiredScopeAndAdditionalScopeThenThrowOAuth2AuthenticationException() {
		Jwt jwt = createJwt(new HashSet<>(Arrays.asList("client.create", "scope1")));
		OAuth2AccessToken jwtAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), jwt.getClaim(OAuth2ParameterNames.SCOPE));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations
			.authorization(registeredClient, jwtAccessToken, jwt.getClaims())
			.build();
		given(this.authorizationService.findByToken(eq(jwtAccessToken.getTokenValue()),
				eq(OAuth2TokenType.ACCESS_TOKEN)))
			.willReturn(authorization);

		JwtAuthenticationToken principal = new JwtAuthenticationToken(jwt,
				AuthorityUtils.createAuthorityList("SCOPE_client.create", "SCOPE_scope1"));
		OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.builder()
			.redirectUri("https://client.example.com")
			.build();

		OAuth2ClientRegistrationAuthenticationToken authentication = new OAuth2ClientRegistrationAuthenticationToken(
				principal, clientRegistration);

		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.extracting(OAuth2AuthenticationException::getError)
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
		verify(this.authorizationService).findByToken(eq(jwtAccessToken.getTokenValue()),
				eq(OAuth2TokenType.ACCESS_TOKEN));
	}

	@Test
	public void authenticateWhenInvalidRedirectUriThenThrowOAuth2AuthenticationException() {
		Jwt jwt = createJwtClientRegistration();
		OAuth2AccessToken jwtAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), jwt.getClaim(OAuth2ParameterNames.SCOPE));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations
			.authorization(registeredClient, jwtAccessToken, jwt.getClaims())
			.build();
		given(this.authorizationService.findByToken(eq(jwtAccessToken.getTokenValue()),
				eq(OAuth2TokenType.ACCESS_TOKEN)))
			.willReturn(authorization);

		JwtAuthenticationToken principal = new JwtAuthenticationToken(jwt,
				AuthorityUtils.createAuthorityList("SCOPE_client.create"));
		// @formatter:off
		OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.builder()
				.redirectUri("invalid uri")
				.build();
		// @formatter:on

		OAuth2ClientRegistrationAuthenticationToken authentication = new OAuth2ClientRegistrationAuthenticationToken(
				principal, clientRegistration);

		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.extracting(OAuth2AuthenticationException::getError)
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_REDIRECT_URI);
				assertThat(error.getDescription()).contains(OAuth2ClientMetadataClaimNames.REDIRECT_URIS);
			});
		verify(this.authorizationService).findByToken(eq(jwtAccessToken.getTokenValue()),
				eq(OAuth2TokenType.ACCESS_TOKEN));
	}

	@Test
	public void authenticateWhenRedirectUriContainsFragmentThenThrowOAuth2AuthenticationException() {
		Jwt jwt = createJwtClientRegistration();
		OAuth2AccessToken jwtAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), jwt.getClaim(OAuth2ParameterNames.SCOPE));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations
			.authorization(registeredClient, jwtAccessToken, jwt.getClaims())
			.build();
		given(this.authorizationService.findByToken(eq(jwtAccessToken.getTokenValue()),
				eq(OAuth2TokenType.ACCESS_TOKEN)))
			.willReturn(authorization);

		JwtAuthenticationToken principal = new JwtAuthenticationToken(jwt,
				AuthorityUtils.createAuthorityList("SCOPE_client.create"));
		// @formatter:off
		OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.builder()
				.redirectUri("https://client.example.com#fragment")
				.build();
		// @formatter:on

		OAuth2ClientRegistrationAuthenticationToken authentication = new OAuth2ClientRegistrationAuthenticationToken(
				principal, clientRegistration);

		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.extracting(OAuth2AuthenticationException::getError)
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_REDIRECT_URI);
				assertThat(error.getDescription()).contains(OAuth2ClientMetadataClaimNames.REDIRECT_URIS);
			});
		verify(this.authorizationService).findByToken(eq(jwtAccessToken.getTokenValue()),
				eq(OAuth2TokenType.ACCESS_TOKEN));
	}

	@Test
	public void authenticateWhenValidAccessTokenThenReturnClientRegistration() {
		Jwt jwt = createJwtClientRegistration();
		OAuth2AccessToken jwtAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), jwt.getClaim(OAuth2ParameterNames.SCOPE));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations
			.authorization(registeredClient, jwtAccessToken, jwt.getClaims())
			.build();
		given(this.authorizationService.findByToken(eq(jwtAccessToken.getTokenValue()),
				eq(OAuth2TokenType.ACCESS_TOKEN)))
			.willReturn(authorization);

		JwtAuthenticationToken principal = new JwtAuthenticationToken(jwt,
				AuthorityUtils.createAuthorityList("SCOPE_client.create"));
		// @formatter:off
		OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.builder()
				.clientName("client-name")
				.redirectUri("https://client.example.com")
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.scope("scope1")
				.scope("scope2")
				.build();
		// @formatter:on

		OAuth2ClientRegistrationAuthenticationToken authentication = new OAuth2ClientRegistrationAuthenticationToken(
				principal, clientRegistration);
		OAuth2ClientRegistrationAuthenticationToken authenticationResult = (OAuth2ClientRegistrationAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		ArgumentCaptor<RegisteredClient> registeredClientCaptor = ArgumentCaptor.forClass(RegisteredClient.class);
		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);

		verify(this.authorizationService).findByToken(eq(jwtAccessToken.getTokenValue()),
				eq(OAuth2TokenType.ACCESS_TOKEN));
		verify(this.registeredClientRepository).save(registeredClientCaptor.capture());
		verify(this.authorizationService).save(authorizationCaptor.capture());
		verify(this.passwordEncoder).encode(any());

		// assert "initial" access token is invalidated
		OAuth2Authorization authorizationResult = authorizationCaptor.getValue();
		assertThat(authorizationResult.getAccessToken().isInvalidated()).isTrue();
		if (authorizationResult.getRefreshToken() != null) {
			assertThat(authorizationResult.getRefreshToken().isInvalidated()).isTrue();
		}

		assertClientRegistration(clientRegistration, authenticationResult.getClientRegistration(),
				registeredClientCaptor.getValue());
	}

	@Test
	public void authenticateWhenOpenRegistrationThenReturnClientRegistration() {
		this.authenticationProvider.setOpenRegistrationAllowed(true);

		// @formatter:off
		OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.builder()
				.clientName("client-name")
				.redirectUri("https://client.example.com")
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.scope("scope1")
				.scope("scope2")
				.build();
		// @formatter:on

		OAuth2ClientRegistrationAuthenticationToken authentication = new OAuth2ClientRegistrationAuthenticationToken(
				null, clientRegistration);
		OAuth2ClientRegistrationAuthenticationToken authenticationResult = (OAuth2ClientRegistrationAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		ArgumentCaptor<RegisteredClient> registeredClientCaptor = ArgumentCaptor.forClass(RegisteredClient.class);

		verifyNoInteractions(this.authorizationService);
		verify(this.registeredClientRepository).save(registeredClientCaptor.capture());
		verify(this.passwordEncoder).encode(any());

		assertClientRegistration(clientRegistration, authenticationResult.getClientRegistration(),
				registeredClientCaptor.getValue());
	}

	private static void assertClientRegistration(OAuth2ClientRegistration clientRegistrationRequest,
			OAuth2ClientRegistration clientRegistrationResult, RegisteredClient registeredClient) {

		assertThat(registeredClient.getId()).isNotNull();
		assertThat(registeredClient.getClientId()).isNotNull();
		assertThat(registeredClient.getClientIdIssuedAt()).isNotNull();
		assertThat(registeredClient.getClientSecret()).isNotNull();
		assertThat(registeredClient.getClientName()).isEqualTo(clientRegistrationRequest.getClientName());
		assertThat(registeredClient.getClientAuthenticationMethods())
			.containsExactly(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		assertThat(registeredClient.getRedirectUris()).containsExactly("https://client.example.com");
		assertThat(registeredClient.getAuthorizationGrantTypes()).containsExactlyInAnyOrder(
				AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.CLIENT_CREDENTIALS);
		assertThat(registeredClient.getScopes()).containsExactlyInAnyOrder("scope1", "scope2");
		assertThat(registeredClient.getClientSettings().isRequireProofKey()).isTrue();
		assertThat(registeredClient.getClientSettings().isRequireAuthorizationConsent()).isTrue();

		assertThat(clientRegistrationResult.getClientId()).isEqualTo(registeredClient.getClientId());
		assertThat(clientRegistrationResult.getClientIdIssuedAt()).isEqualTo(registeredClient.getClientIdIssuedAt());
		assertThat(clientRegistrationResult.getClientSecret()).isEqualTo(registeredClient.getClientSecret());
		assertThat(clientRegistrationResult.getClientSecretExpiresAt())
			.isEqualTo(registeredClient.getClientSecretExpiresAt());
		assertThat(clientRegistrationResult.getClientName()).isEqualTo(registeredClient.getClientName());
		assertThat(clientRegistrationResult.getRedirectUris())
			.containsExactlyInAnyOrderElementsOf(registeredClient.getRedirectUris());

		List<String> grantTypes = new ArrayList<>();
		registeredClient.getAuthorizationGrantTypes()
			.forEach((authorizationGrantType) -> grantTypes.add(authorizationGrantType.getValue()));
		assertThat(clientRegistrationResult.getGrantTypes()).containsExactlyInAnyOrderElementsOf(grantTypes);

		assertThat(clientRegistrationResult.getResponseTypes())
			.containsExactly(OAuth2AuthorizationResponseType.CODE.getValue());
		assertThat(clientRegistrationResult.getScopes())
			.containsExactlyInAnyOrderElementsOf(registeredClient.getScopes());
		assertThat(clientRegistrationResult.getTokenEndpointAuthenticationMethod())
			.isEqualTo(registeredClient.getClientAuthenticationMethods().iterator().next().getValue());
	}

	private static Jwt createJwtClientRegistration() {
		return createJwt(Collections.singleton("client.create"));
	}

	private static Jwt createJwt(Set<String> scopes) {
		// @formatter:off
		JwsHeader jwsHeader = TestJwsHeaders.jwsHeader()
				.build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet()
				.claim(OAuth2ParameterNames.SCOPE, scopes)
				.build();
		Jwt jwt = Jwt.withTokenValue("jwt-access-token")
				.headers((headers) -> headers.putAll(jwsHeader.getHeaders()))
				.claims((claims) -> claims.putAll(jwtClaimsSet.getClaims()))
				.build();
		// @formatter:on
		return jwt;
	}

}
