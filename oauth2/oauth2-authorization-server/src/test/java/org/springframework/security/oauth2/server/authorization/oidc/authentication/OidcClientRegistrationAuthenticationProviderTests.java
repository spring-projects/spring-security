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
import org.mockito.ArgumentCaptor;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
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
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
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
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.util.UriComponentsBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link OidcClientRegistrationAuthenticationProvider}.
 *
 * @author Ovidiu Popa
 * @author Joe Grandja
 */
public class OidcClientRegistrationAuthenticationProviderTests {

	private RegisteredClientRepository registeredClientRepository;

	private OAuth2AuthorizationService authorizationService;

	private JwtEncoder jwtEncoder;

	private OAuth2TokenGenerator<?> tokenGenerator;

	private PasswordEncoder passwordEncoder;

	private AuthorizationServerSettings authorizationServerSettings;

	private OidcClientRegistrationAuthenticationProvider authenticationProvider;

	@BeforeEach
	public void setUp() {
		this.registeredClientRepository = mock(RegisteredClientRepository.class);
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.jwtEncoder = mock(JwtEncoder.class);
		JwtGenerator jwtGenerator = new JwtGenerator(this.jwtEncoder);
		this.tokenGenerator = spy(new OAuth2TokenGenerator<Jwt>() {
			@Override
			public Jwt generate(OAuth2TokenContext context) {
				return jwtGenerator.generate(context);
			}
		});
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
		this.authorizationServerSettings = AuthorizationServerSettings.builder().issuer("https://provider.com").build();
		AuthorizationServerContextHolder
			.setContext(new TestAuthorizationServerContext(this.authorizationServerSettings, null));
		this.authenticationProvider = new OidcClientRegistrationAuthenticationProvider(this.registeredClientRepository,
				this.authorizationService, this.tokenGenerator);
		this.authenticationProvider.setPasswordEncoder(this.passwordEncoder);
	}

	@AfterEach
	public void cleanup() {
		AuthorizationServerContextHolder.resetContext();
	}

	@Test
	public void constructorWhenRegisteredClientRepositoryNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new OidcClientRegistrationAuthenticationProvider(null, this.authorizationService,
					this.tokenGenerator))
			.withMessage("registeredClientRepository cannot be null");
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new OidcClientRegistrationAuthenticationProvider(this.registeredClientRepository, null,
					this.tokenGenerator))
			.withMessage("authorizationService cannot be null");
	}

	@Test
	public void constructorWhenTokenGeneratorNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new OidcClientRegistrationAuthenticationProvider(this.registeredClientRepository,
					this.authorizationService, null))
			.withMessage("tokenGenerator cannot be null");
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
		assertThatThrownBy(() -> this.authenticationProvider.setPasswordEncoder(null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("passwordEncoder cannot be null");
	}

	@Test
	public void supportsWhenTypeOidcClientRegistrationAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OidcClientRegistrationAuthenticationToken.class)).isTrue();
	}

	@Test
	public void authenticateWhenPrincipalNotOAuth2TokenAuthenticationTokenThenThrowOAuth2AuthenticationException() {
		TestingAuthenticationToken principal = new TestingAuthenticationToken("principal", "credentials");
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
			.redirectUri("https://client.example.com")
			.build();

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				principal, clientRegistration);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
	}

	@Test
	public void authenticateWhenPrincipalNotAuthenticatedThenThrowOAuth2AuthenticationException() {
		JwtAuthenticationToken principal = new JwtAuthenticationToken(createJwtClientRegistration());
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
			.redirectUri("https://client.example.com")
			.build();

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				principal, clientRegistration);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
	}

	@Test
	public void authenticateWhenAccessTokenNotFoundThenThrowOAuth2AuthenticationException() {
		Jwt jwt = createJwtClientRegistration();
		JwtAuthenticationToken principal = new JwtAuthenticationToken(jwt,
				AuthorityUtils.createAuthorityList("SCOPE_client.create"));
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
			.redirectUri("https://client.example.com")
			.build();

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				principal, clientRegistration);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
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
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
			.redirectUri("https://client.example.com")
			.build();

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				principal, clientRegistration);

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
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
			.redirectUri("https://client.example.com")
			.build();

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				principal, clientRegistration);

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
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
			.redirectUri("https://client.example.com")
			.build();

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				principal, clientRegistration);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
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
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.redirectUri("invalid uri")
				.build();
		// @formatter:on

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				principal, clientRegistration);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_REDIRECT_URI);
				assertThat(error.getDescription()).contains(OidcClientMetadataClaimNames.REDIRECT_URIS);
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
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.redirectUri("https://client.example.com#fragment")
				.build();
		// @formatter:on

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				principal, clientRegistration);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_REDIRECT_URI);
				assertThat(error.getDescription()).contains(OidcClientMetadataClaimNames.REDIRECT_URIS);
			});
		verify(this.authorizationService).findByToken(eq(jwtAccessToken.getTokenValue()),
				eq(OAuth2TokenType.ACCESS_TOKEN));
	}

	@Test
	public void authenticateWhenInvalidPostLogoutRedirectUriThenThrowOAuth2AuthenticationException() {
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
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.redirectUri("https://client.example.com")
				.postLogoutRedirectUri("invalid uri")
				.build();
		// @formatter:on

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				principal, clientRegistration);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo("invalid_client_metadata");
				assertThat(error.getDescription()).contains(OidcClientMetadataClaimNames.POST_LOGOUT_REDIRECT_URIS);
			});
		verify(this.authorizationService).findByToken(eq(jwtAccessToken.getTokenValue()),
				eq(OAuth2TokenType.ACCESS_TOKEN));
	}

	@Test
	public void authenticateWhenPostLogoutRedirectUriContainsFragmentThenThrowOAuth2AuthenticationException() {
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
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.redirectUri("https://client.example.com")
				.postLogoutRedirectUri("https://client.example.com/oidc-post-logout#fragment")
				.build();
		// @formatter:on

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				principal, clientRegistration);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo("invalid_client_metadata");
				assertThat(error.getDescription()).contains(OidcClientMetadataClaimNames.POST_LOGOUT_REDIRECT_URIS);
			});
		verify(this.authorizationService).findByToken(eq(jwtAccessToken.getTokenValue()),
				eq(OAuth2TokenType.ACCESS_TOKEN));
	}

	@Test
	public void authenticateWhenInvalidTokenEndpointAuthenticationMethodThenThrowOAuth2AuthenticationException() {
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
		OidcClientRegistration.Builder builder = OidcClientRegistration.builder()
				.redirectUri("https://client.example.com");
		// @formatter:on

		String invalidClientMetadataErrorCode = "invalid_client_metadata";

		// @formatter:off
		builder
				.tokenEndpointAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue())
				.tokenEndpointAuthenticationSigningAlgorithm(MacAlgorithm.HS256.getName());
		assertWhenClientRegistrationRequestInvalidThenThrowOAuth2AuthenticationException(principal, builder.build(),
				invalidClientMetadataErrorCode, OidcClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD);
		// @formatter:on

		// @formatter:off
		builder
				.tokenEndpointAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue())
				.tokenEndpointAuthenticationSigningAlgorithm("none");
		assertWhenClientRegistrationRequestInvalidThenThrowOAuth2AuthenticationException(principal, builder.build(),
				invalidClientMetadataErrorCode, OidcClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD);
		// @formatter:on

		// @formatter:off
		builder
				.tokenEndpointAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue())
				.tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256.getName());
		assertWhenClientRegistrationRequestInvalidThenThrowOAuth2AuthenticationException(principal, builder.build(),
				invalidClientMetadataErrorCode, OidcClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD);
		// @formatter:on

		// @formatter:off
		builder
				.tokenEndpointAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue())
				.jwkSetUrl("https://client.example.com/jwks")
				.tokenEndpointAuthenticationSigningAlgorithm(MacAlgorithm.HS256.getName());
		assertWhenClientRegistrationRequestInvalidThenThrowOAuth2AuthenticationException(principal, builder.build(),
				invalidClientMetadataErrorCode, OidcClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD);
		// @formatter:on

		// @formatter:off
		builder
				.tokenEndpointAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue())
				.tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256.getName());
		assertWhenClientRegistrationRequestInvalidThenThrowOAuth2AuthenticationException(principal, builder.build(),
				invalidClientMetadataErrorCode, OidcClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD);
		// @formatter:on
	}

	private void assertWhenClientRegistrationRequestInvalidThenThrowOAuth2AuthenticationException(
			Authentication principal, OidcClientRegistration clientRegistration, String errorCode,
			String errorDescription) {

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				principal, clientRegistration);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(errorCode);
				assertThat(error.getDescription()).contains(errorDescription);
			});
	}

	@Test
	public void authenticateWhenTokenEndpointAuthenticationSigningAlgorithmNotProvidedThenDefaults() {
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
		given(this.jwtEncoder.encode(any())).willReturn(createJwtClientConfiguration());

		JwtAuthenticationToken principal = new JwtAuthenticationToken(jwt,
				AuthorityUtils.createAuthorityList("SCOPE_client.create"));
		// @formatter:off
		OidcClientRegistration.Builder builder = OidcClientRegistration.builder()
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.redirectUri("https://client.example.com")
				.scope("scope1");
		// @formatter:on

		// @formatter:off
		builder
				.tokenEndpointAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue());
		// @formatter:on
		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				principal, builder.build());
		OidcClientRegistrationAuthenticationToken authenticationResult = (OidcClientRegistrationAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);
		assertThat(authenticationResult.getClientRegistration().getTokenEndpointAuthenticationSigningAlgorithm())
			.isEqualTo(MacAlgorithm.HS256.getName());
		assertThat(authenticationResult.getClientRegistration().getClientSecret()).isNotNull();
		verify(this.passwordEncoder).encode(any());
		reset(this.passwordEncoder);

		// @formatter:off
		builder
				.tokenEndpointAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue())
				.jwkSetUrl("https://client.example.com/jwks");
		// @formatter:on
		authentication = new OidcClientRegistrationAuthenticationToken(principal, builder.build());
		authenticationResult = (OidcClientRegistrationAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);
		assertThat(authenticationResult.getClientRegistration().getTokenEndpointAuthenticationSigningAlgorithm())
			.isEqualTo(SignatureAlgorithm.RS256.getName());
		assertThat(authenticationResult.getClientRegistration().getClientSecret()).isNull();
		verifyNoInteractions(this.passwordEncoder);
	}

	@Test
	public void authenticateWhenRegistrationAccessTokenNotGeneratedThenThrowOAuth2AuthenticationException() {
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

		doReturn(null).when(this.tokenGenerator).generate(any());

		JwtAuthenticationToken principal = new JwtAuthenticationToken(jwt,
				AuthorityUtils.createAuthorityList("SCOPE_client.create"));
		// @formatter:off
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.clientName("client-name")
				.redirectUri("https://client.example.com")
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.scope("scope1")
				.scope("scope2")
				.build();
		// @formatter:on

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				principal, clientRegistration);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.SERVER_ERROR);
				assertThat(error.getDescription())
					.contains("The token generator failed to generate the registration access token.");
			});
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
		given(this.jwtEncoder.encode(any())).willReturn(createJwtClientConfiguration());

		JwtAuthenticationToken principal = new JwtAuthenticationToken(jwt,
				AuthorityUtils.createAuthorityList("SCOPE_client.create"));
		// @formatter:off
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.clientName("client-name")
				.redirectUri("https://client.example.com")
				.postLogoutRedirectUri("https://client.example.com/oidc-post-logout")
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.scope("scope1")
				.scope("scope2")
				.build();
		// @formatter:on

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				principal, clientRegistration);
		OidcClientRegistrationAuthenticationToken authenticationResult = (OidcClientRegistrationAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		ArgumentCaptor<RegisteredClient> registeredClientCaptor = ArgumentCaptor.forClass(RegisteredClient.class);
		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);

		verify(this.authorizationService).findByToken(eq(jwtAccessToken.getTokenValue()),
				eq(OAuth2TokenType.ACCESS_TOKEN));
		verify(this.registeredClientRepository).save(registeredClientCaptor.capture());
		verify(this.authorizationService, times(2)).save(authorizationCaptor.capture());
		verify(this.jwtEncoder).encode(any());
		verify(this.passwordEncoder).encode(any());

		// assert "registration" access token, which should be used for subsequent calls
		// to client configuration endpoint
		OAuth2Authorization authorizationResult = authorizationCaptor.getAllValues().get(0);
		assertThat(authorizationResult.getAccessToken().getToken().getScopes()).containsExactly("client.read");
		assertThat(authorizationResult.getAccessToken().isActive()).isTrue();
		assertThat(authorizationResult.getRefreshToken()).isNull();

		// assert "initial" access token is invalidated
		authorizationResult = authorizationCaptor.getAllValues().get(1);
		assertThat(authorizationResult.getAccessToken().isInvalidated()).isTrue();
		if (authorizationResult.getRefreshToken() != null) {
			assertThat(authorizationResult.getRefreshToken().isInvalidated()).isTrue();
		}

		RegisteredClient registeredClientResult = registeredClientCaptor.getValue();
		assertThat(registeredClientResult.getId()).isNotNull();
		assertThat(registeredClientResult.getClientId()).isNotNull();
		assertThat(registeredClientResult.getClientIdIssuedAt()).isNotNull();
		assertThat(registeredClientResult.getClientSecret()).isNotNull();
		assertThat(registeredClientResult.getClientName()).isEqualTo(clientRegistration.getClientName());
		assertThat(registeredClientResult.getClientAuthenticationMethods())
			.containsExactly(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		assertThat(registeredClientResult.getRedirectUris()).containsExactly("https://client.example.com");
		assertThat(registeredClientResult.getPostLogoutRedirectUris())
			.containsExactly("https://client.example.com/oidc-post-logout");
		assertThat(registeredClientResult.getAuthorizationGrantTypes()).containsExactlyInAnyOrder(
				AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.CLIENT_CREDENTIALS);
		assertThat(registeredClientResult.getScopes()).containsExactlyInAnyOrder("scope1", "scope2");
		assertThat(registeredClientResult.getClientSettings().isRequireProofKey()).isTrue();
		assertThat(registeredClientResult.getClientSettings().isRequireAuthorizationConsent()).isTrue();
		assertThat(registeredClientResult.getTokenSettings().getIdTokenSignatureAlgorithm())
			.isEqualTo(SignatureAlgorithm.RS256);

		OidcClientRegistration clientRegistrationResult = authenticationResult.getClientRegistration();
		assertThat(clientRegistrationResult.getClientId()).isEqualTo(registeredClientResult.getClientId());
		assertThat(clientRegistrationResult.getClientIdIssuedAt())
			.isEqualTo(registeredClientResult.getClientIdIssuedAt());
		assertThat(clientRegistrationResult.getClientSecret()).isEqualTo(registeredClientResult.getClientSecret());
		assertThat(clientRegistrationResult.getClientSecretExpiresAt())
			.isEqualTo(registeredClientResult.getClientSecretExpiresAt());
		assertThat(clientRegistrationResult.getClientName()).isEqualTo(registeredClientResult.getClientName());
		assertThat(clientRegistrationResult.getRedirectUris())
			.containsExactlyInAnyOrderElementsOf(registeredClientResult.getRedirectUris());
		assertThat(clientRegistrationResult.getPostLogoutRedirectUris())
			.containsExactlyInAnyOrderElementsOf(registeredClientResult.getPostLogoutRedirectUris());

		List<String> grantTypes = new ArrayList<>();
		registeredClientResult.getAuthorizationGrantTypes()
			.forEach((authorizationGrantType) -> grantTypes.add(authorizationGrantType.getValue()));
		assertThat(clientRegistrationResult.getGrantTypes()).containsExactlyInAnyOrderElementsOf(grantTypes);

		assertThat(clientRegistrationResult.getResponseTypes())
			.containsExactly(OAuth2AuthorizationResponseType.CODE.getValue());
		assertThat(clientRegistrationResult.getScopes())
			.containsExactlyInAnyOrderElementsOf(registeredClientResult.getScopes());
		assertThat(clientRegistrationResult.getTokenEndpointAuthenticationMethod())
			.isEqualTo(registeredClientResult.getClientAuthenticationMethods().iterator().next().getValue());
		assertThat(clientRegistrationResult.getIdTokenSignedResponseAlgorithm())
			.isEqualTo(registeredClientResult.getTokenSettings().getIdTokenSignatureAlgorithm().getName());

		AuthorizationServerContext authorizationServerContext = AuthorizationServerContextHolder.getContext();
		String expectedRegistrationClientUrl = UriComponentsBuilder
			.fromUriString(authorizationServerContext.getIssuer())
			.path(authorizationServerContext.getAuthorizationServerSettings().getOidcClientRegistrationEndpoint())
			.queryParam(OAuth2ParameterNames.CLIENT_ID, registeredClientResult.getClientId())
			.toUriString();

		assertThat(clientRegistrationResult.getRegistrationClientUrl().toString())
			.isEqualTo(expectedRegistrationClientUrl);
		assertThat(clientRegistrationResult.getRegistrationAccessToken()).isEqualTo(jwt.getTokenValue());
	}

	private static Jwt createJwtClientRegistration() {
		return createJwt(Collections.singleton("client.create"));
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
