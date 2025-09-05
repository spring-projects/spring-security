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

package org.springframework.security.oauth2.server.authorization.oidc.authentication;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.TestJwsHeaders;
import org.springframework.security.oauth2.jwt.TestJwtClaimsSets;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.context.TestAuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.util.UriComponentsBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link OidcClientConfigurationAuthenticationProvider}.
 *
 * @author Ovidiu Popa
 * @author Joe Grandja
 */
public class OidcClientConfigurationAuthenticationProviderTests {

	private RegisteredClientRepository registeredClientRepository;

	private OAuth2AuthorizationService authorizationService;

	private AuthorizationServerSettings authorizationServerSettings;

	private OidcClientConfigurationAuthenticationProvider authenticationProvider;

	@BeforeEach
	public void setUp() {
		this.registeredClientRepository = mock(RegisteredClientRepository.class);
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.authorizationServerSettings = AuthorizationServerSettings.builder().issuer("https://provider.com").build();
		AuthorizationServerContextHolder
			.setContext(new TestAuthorizationServerContext(this.authorizationServerSettings, null));
		this.authenticationProvider = new OidcClientConfigurationAuthenticationProvider(this.registeredClientRepository,
				this.authorizationService);
	}

	@AfterEach
	public void cleanup() {
		AuthorizationServerContextHolder.resetContext();
	}

	@Test
	public void constructorWhenRegisteredClientRepositoryNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new OidcClientConfigurationAuthenticationProvider(null, this.authorizationService))
			.withMessage("registeredClientRepository cannot be null");
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new OidcClientConfigurationAuthenticationProvider(this.registeredClientRepository, null))
			.withMessage("authorizationService cannot be null");
	}

	@Test
	public void supportsWhenTypeOidcClientRegistrationAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OidcClientRegistrationAuthenticationToken.class)).isTrue();
	}

	@Test
	public void setClientRegistrationConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.authenticationProvider.setClientRegistrationConverter(null))
			.withMessage("clientRegistrationConverter cannot be null");
	}

	@Test
	public void authenticateWhenPrincipalNotOAuth2TokenAuthenticationTokenThenThrowOAuth2AuthenticationException() {
		TestingAuthenticationToken principal = new TestingAuthenticationToken("principal", "credentials");

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				principal, "client-id");

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
	}

	@Test
	public void authenticateWhenPrincipalNotAuthenticatedThenThrowOAuth2AuthenticationException() {
		JwtAuthenticationToken principal = new JwtAuthenticationToken(createJwtClientConfiguration());

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				principal, "client-id");

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
	}

	@Test
	public void authenticateWhenAccessTokenNotFoundThenThrowOAuth2AuthenticationException() {
		Jwt jwt = createJwtClientConfiguration();
		JwtAuthenticationToken principal = new JwtAuthenticationToken(jwt,
				AuthorityUtils.createAuthorityList("SCOPE_client.read"));

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				principal, "client-id");

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
		verify(this.authorizationService).findByToken(eq(jwt.getTokenValue()), eq(OAuth2TokenType.ACCESS_TOKEN));
	}

	@Test
	public void authenticateWhenAccessTokenNotActiveThenThrowOAuth2AuthenticationException() {
		Jwt jwt = createJwtClientConfiguration();
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
				AuthorityUtils.createAuthorityList("SCOPE_client.read"));

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				principal, registeredClient.getClientId());

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
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

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				principal, registeredClient.getClientId());

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INSUFFICIENT_SCOPE);
		verify(this.authorizationService).findByToken(eq(jwtAccessToken.getTokenValue()),
				eq(OAuth2TokenType.ACCESS_TOKEN));
	}

	@Test
	public void authenticateWhenAccessTokenContainsRequiredScopeAndAdditionalScopeThenThrowOAuth2AuthenticationException() {
		Jwt jwt = createJwt(new HashSet<>(Arrays.asList("client.read", "scope1")));
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
				AuthorityUtils.createAuthorityList("SCOPE_client.read", "SCOPE_scope1"));

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				principal, registeredClient.getClientId());

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
		verify(this.authorizationService).findByToken(eq(jwtAccessToken.getTokenValue()),
				eq(OAuth2TokenType.ACCESS_TOKEN));
	}

	@Test
	public void authenticateWhenRegisteredClientNotFoundThenThrowOAuth2AuthenticationException() {
		Jwt jwt = createJwtClientConfiguration();
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
				AuthorityUtils.createAuthorityList("SCOPE_client.read"));

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				principal, registeredClient.getClientId());

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
		verify(this.authorizationService).findByToken(eq(jwtAccessToken.getTokenValue()),
				eq(OAuth2TokenType.ACCESS_TOKEN));
		verify(this.registeredClientRepository).findByClientId(eq(registeredClient.getClientId()));
	}

	@Test
	public void authenticateWhenClientIdNotEqualToAuthorizedClientThenThrowOAuth2AuthenticationException() {
		Jwt jwt = createJwtClientConfiguration();
		OAuth2AccessToken jwtAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), jwt.getClaim(OAuth2ParameterNames.SCOPE));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		RegisteredClient authorizedRegisteredClient = TestRegisteredClients.registeredClient()
			.id("registration-2")
			.clientId("client-2")
			.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations
			.authorization(authorizedRegisteredClient, jwtAccessToken, jwt.getClaims())
			.build();
		given(this.authorizationService.findByToken(eq(jwtAccessToken.getTokenValue()),
				eq(OAuth2TokenType.ACCESS_TOKEN)))
			.willReturn(authorization);
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);

		JwtAuthenticationToken principal = new JwtAuthenticationToken(jwt,
				AuthorityUtils.createAuthorityList("SCOPE_client.read"));

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				principal, registeredClient.getClientId());

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
		verify(this.authorizationService).findByToken(eq(jwtAccessToken.getTokenValue()),
				eq(OAuth2TokenType.ACCESS_TOKEN));
		verify(this.registeredClientRepository).findByClientId(eq(registeredClient.getClientId()));
	}

	@Test
	public void authenticateWhenValidAccessTokenThenReturnClientRegistration() {
		Jwt jwt = createJwtClientConfiguration();
		OAuth2AccessToken jwtAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), jwt.getClaim(OAuth2ParameterNames.SCOPE));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.clientAuthenticationMethods((clientAuthenticationMethods) -> {
				clientAuthenticationMethods.clear();
				clientAuthenticationMethods.add(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
			})
			.clientSettings(ClientSettings.builder()
				.tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS512)
				.jwkSetUrl("https://client.example.com/jwks")
				.build())
			.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations
			.authorization(registeredClient, jwtAccessToken, jwt.getClaims())
			.build();
		given(this.authorizationService.findByToken(eq(jwtAccessToken.getTokenValue()),
				eq(OAuth2TokenType.ACCESS_TOKEN)))
			.willReturn(authorization);
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);

		JwtAuthenticationToken principal = new JwtAuthenticationToken(jwt,
				AuthorityUtils.createAuthorityList("SCOPE_client.read"));

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				principal, registeredClient.getClientId());

		OidcClientRegistrationAuthenticationToken authenticationResult = (OidcClientRegistrationAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		verify(this.authorizationService).findByToken(eq(jwtAccessToken.getTokenValue()),
				eq(OAuth2TokenType.ACCESS_TOKEN));
		verify(this.registeredClientRepository).findByClientId(eq(registeredClient.getClientId()));

		// verify that the "registration" access token is not invalidated after it is used
		verify(this.authorizationService, never()).save(eq(authorization));
		assertThat(authorization.getAccessToken().isInvalidated()).isFalse();

		OidcClientRegistration clientRegistrationResult = authenticationResult.getClientRegistration();
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
		assertThat(clientRegistrationResult.getTokenEndpointAuthenticationSigningAlgorithm())
			.isEqualTo(registeredClient.getClientSettings().getTokenEndpointAuthenticationSigningAlgorithm().getName());
		assertThat(clientRegistrationResult.getJwkSetUrl().toString())
			.isEqualTo(registeredClient.getClientSettings().getJwkSetUrl());
		assertThat(clientRegistrationResult.getIdTokenSignedResponseAlgorithm())
			.isEqualTo(registeredClient.getTokenSettings().getIdTokenSignatureAlgorithm().getName());

		AuthorizationServerContext authorizationServerContext = AuthorizationServerContextHolder.getContext();
		String expectedRegistrationClientUrl = UriComponentsBuilder
			.fromUriString(authorizationServerContext.getIssuer())
			.path(authorizationServerContext.getAuthorizationServerSettings().getOidcClientRegistrationEndpoint())
			.queryParam(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId())
			.toUriString();

		assertThat(clientRegistrationResult.getRegistrationClientUrl().toString())
			.isEqualTo(expectedRegistrationClientUrl);
		assertThat(clientRegistrationResult.getRegistrationAccessToken()).isNull();
	}

	private static Jwt createJwtClientConfiguration() {
		return createJwt(Collections.singleton("client.read"));
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
