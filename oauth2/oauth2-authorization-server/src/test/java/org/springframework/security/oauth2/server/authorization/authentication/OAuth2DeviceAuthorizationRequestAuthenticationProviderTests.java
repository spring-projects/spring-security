/*
 * Copyright 2020-2023 the original author or authors.
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

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.context.TestAuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests for {@link OAuth2DeviceAuthorizationRequestAuthenticationProvider}.
 *
 * @author Steve Riesenberg
 */
public class OAuth2DeviceAuthorizationRequestAuthenticationProviderTests {

	private static final String AUTHORIZATION_URI = "/oauth2/device_authorization";

	private static final String DEVICE_CODE = "EfYu_0jEL";

	private static final String USER_CODE = "BCDF-GHJK";

	private OAuth2AuthorizationService authorizationService;

	private OAuth2DeviceAuthorizationRequestAuthenticationProvider authenticationProvider;

	@BeforeEach
	public void setUp() {
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.authenticationProvider = new OAuth2DeviceAuthorizationRequestAuthenticationProvider(
				this.authorizationService);
		mockAuthorizationServerContext();
	}

	@AfterEach
	public void tearDown() {
		AuthorizationServerContextHolder.resetContext();
	}

	@Test
	public void constructorWhenAuthorizationServiceIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2DeviceAuthorizationRequestAuthenticationProvider(null))
				.withMessage("authorizationService cannot be null");
		// @formatter:on
	}

	@Test
	public void setDeviceCodeGeneratorWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authenticationProvider.setDeviceCodeGenerator(null))
				.withMessage("deviceCodeGenerator cannot be null");
		// @formatter:on
	}

	@Test
	public void setUserCodeGeneratorWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authenticationProvider.setUserCodeGenerator(null))
				.withMessage("userCodeGenerator cannot be null");
		// @formatter:on
	}

	@Test
	public void supportsWhenTypeOAuth2DeviceAuthorizationRequestAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2DeviceAuthorizationRequestAuthenticationToken.class))
			.isTrue();
	}

	@Test
	public void authenticateWhenClientNotAuthenticatedThenThrowOAuth2AuthenticationException() {
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken("client-1",
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null, null);
		OAuth2DeviceAuthorizationRequestAuthenticationToken authentication = new OAuth2DeviceAuthorizationRequestAuthenticationToken(
				clientPrincipal, AUTHORIZATION_URI, null, null);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
		// @formatter:on
	}

	@Test
	public void authenticateWhenInvalidGrantTypeThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		Authentication authentication = createAuthentication(registeredClient);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.withMessageContaining(OAuth2ParameterNames.CLIENT_ID)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
		// @formatter:on
	}

	@Test
	public void authenticateWhenInvalidScopesThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
			.build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null);
		Authentication authentication = new OAuth2DeviceAuthorizationRequestAuthenticationToken(clientPrincipal,
				AUTHORIZATION_URI, Collections.singleton("invalid"), null);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.withMessageContaining(OAuth2ParameterNames.SCOPE)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE);
		// @formatter:on
	}

	@Test
	public void authenticateWhenDeviceCodeIsNullThenThrowOAuth2AuthenticationException() {
		@SuppressWarnings("unchecked")
		OAuth2TokenGenerator<OAuth2DeviceCode> deviceCodeGenerator = mock(OAuth2TokenGenerator.class);
		given(deviceCodeGenerator.generate(any(OAuth2TokenContext.class))).willReturn(null);
		this.authenticationProvider.setDeviceCodeGenerator(deviceCodeGenerator);

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
			.build();
		Authentication authentication = createAuthentication(registeredClient);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.withMessageContaining("The token generator failed to generate the device code.")
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.SERVER_ERROR);
		// @formatter:on

		verify(deviceCodeGenerator).generate(any(OAuth2TokenContext.class));
		verifyNoMoreInteractions(deviceCodeGenerator);
		verifyNoInteractions(this.authorizationService);
	}

	@Test
	public void authenticateWhenUserCodeIsNullThenThrowOAuth2AuthenticationException() {
		@SuppressWarnings("unchecked")
		OAuth2TokenGenerator<OAuth2UserCode> userCodeGenerator = mock(OAuth2TokenGenerator.class);
		given(userCodeGenerator.generate(any(OAuth2TokenContext.class))).willReturn(null);
		this.authenticationProvider.setUserCodeGenerator(userCodeGenerator);
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
			.build();
		Authentication authentication = createAuthentication(registeredClient);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.withMessageContaining("The token generator failed to generate the user code.")
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.SERVER_ERROR);
		// @formatter:on

		verify(userCodeGenerator).generate(any(OAuth2TokenContext.class));
		verifyNoMoreInteractions(userCodeGenerator);
		verifyNoInteractions(this.authorizationService);
	}

	@Test
	public void authenticateWhenScopesRequestedThenReturnDeviceCodeAndUserCode() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
			.build();
		Authentication authentication = createAuthentication(registeredClient);
		OAuth2DeviceAuthorizationRequestAuthenticationToken authenticationResult = (OAuth2DeviceAuthorizationRequestAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);
		assertThat(authenticationResult.getPrincipal()).isEqualTo(authentication.getPrincipal());
		assertThat(authenticationResult.getScopes()).hasSameElementsAs(registeredClient.getScopes());
		assertThat(authenticationResult.getDeviceCode().getTokenValue()).hasSize(128);
		// 8 chars + 1 dash
		assertThat(authenticationResult.getUserCode().getTokenValue()).hasSize(9);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		verifyNoMoreInteractions(this.authorizationService);

		OAuth2Authorization authorization = authorizationCaptor.getValue();
		assertThat(authorization.getRegisteredClientId()).isEqualTo(registeredClient.getId());
		assertThat(authorization.getPrincipalName()).isEqualTo(authentication.getName());
		assertThat(authorization.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.DEVICE_CODE);
		assertThat(authorization.getToken(OAuth2DeviceCode.class)).isNotNull();
		assertThat(authorization.getToken(OAuth2UserCode.class)).isNotNull();
		assertThat(authorization.<Set<String>>getAttribute(OAuth2ParameterNames.SCOPE))
			.hasSameElementsAs(registeredClient.getScopes());
	}

	@Test
	public void authenticateWhenNoScopesRequestedThenReturnDeviceCodeAndUserCode() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.scopes(Set::clear)
			.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
			.build();
		Authentication authentication = createAuthentication(registeredClient);
		OAuth2DeviceAuthorizationRequestAuthenticationToken authenticationResult = (OAuth2DeviceAuthorizationRequestAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);
		assertThat(authenticationResult.getPrincipal()).isEqualTo(authentication.getPrincipal());
		assertThat(authenticationResult.getScopes()).hasSameElementsAs(registeredClient.getScopes());
		assertThat(authenticationResult.getDeviceCode().getTokenValue()).hasSize(128);
		// 8 chars + 1 dash
		assertThat(authenticationResult.getUserCode().getTokenValue()).hasSize(9);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		verifyNoMoreInteractions(this.authorizationService);

		OAuth2Authorization authorization = authorizationCaptor.getValue();
		assertThat(authorization.getRegisteredClientId()).isEqualTo(registeredClient.getId());
		assertThat(authorization.getPrincipalName()).isEqualTo(authentication.getName());
		assertThat(authorization.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.DEVICE_CODE);
		assertThat(authorization.getToken(OAuth2DeviceCode.class)).isNotNull();
		assertThat(authorization.getToken(OAuth2UserCode.class)).isNotNull();
		assertThat(authorization.<Set<String>>getAttribute(OAuth2ParameterNames.SCOPE))
			.hasSameElementsAs(registeredClient.getScopes());
	}

	@Test
	public void authenticateWhenDeviceCodeGeneratorSetThenUsed() {
		@SuppressWarnings("unchecked")
		OAuth2TokenGenerator<OAuth2DeviceCode> deviceCodeGenerator = mock(OAuth2TokenGenerator.class);
		given(deviceCodeGenerator.generate(any(OAuth2TokenContext.class))).willReturn(createDeviceCode());
		this.authenticationProvider.setDeviceCodeGenerator(deviceCodeGenerator);

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
			.build();
		Authentication authentication = createAuthentication(registeredClient);
		OAuth2DeviceAuthorizationRequestAuthenticationToken authenticationResult = (OAuth2DeviceAuthorizationRequestAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);
		assertThat(authenticationResult.getPrincipal()).isEqualTo(authentication.getPrincipal());
		assertThat(authenticationResult.getScopes()).hasSameElementsAs(registeredClient.getScopes());
		assertThat(authenticationResult.getDeviceCode().getTokenValue()).isEqualTo(DEVICE_CODE);
		// 8 chars + 1 dash
		assertThat(authenticationResult.getUserCode().getTokenValue()).hasSize(9);

		ArgumentCaptor<OAuth2TokenContext> tokenContextCaptor = ArgumentCaptor.forClass(OAuth2TokenContext.class);
		verify(deviceCodeGenerator).generate(tokenContextCaptor.capture());
		verify(this.authorizationService).save(any(OAuth2Authorization.class));
		verifyNoMoreInteractions(this.authorizationService, deviceCodeGenerator);

		OAuth2TokenContext tokenContext = tokenContextCaptor.getValue();
		assertThat(tokenContext.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(tokenContext.<Authentication>getPrincipal()).isEqualTo(authentication.getPrincipal());
		assertThat(tokenContext.getAuthorizationServerContext()).isNotNull();
		assertThat(tokenContext.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.DEVICE_CODE);
		assertThat(tokenContext.<Authentication>getAuthorizationGrant()).isEqualTo(authentication);
		assertThat(tokenContext.getTokenType())
			.isEqualTo(OAuth2DeviceAuthorizationRequestAuthenticationProvider.DEVICE_CODE_TOKEN_TYPE);
	}

	@Test
	public void authenticateWhenUserCodeGeneratorSetThenUsed() {
		@SuppressWarnings("unchecked")
		OAuth2TokenGenerator<OAuth2UserCode> userCodeGenerator = mock(OAuth2TokenGenerator.class);
		given(userCodeGenerator.generate(any(OAuth2TokenContext.class))).willReturn(createUserCode());
		this.authenticationProvider.setUserCodeGenerator(userCodeGenerator);

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
			.build();
		Authentication authentication = createAuthentication(registeredClient);
		OAuth2DeviceAuthorizationRequestAuthenticationToken authenticationResult = (OAuth2DeviceAuthorizationRequestAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);
		assertThat(authenticationResult.getPrincipal()).isEqualTo(authentication.getPrincipal());
		assertThat(authenticationResult.getScopes()).hasSameElementsAs(registeredClient.getScopes());
		assertThat(authenticationResult.getDeviceCode().getTokenValue()).hasSize(128);
		assertThat(authenticationResult.getUserCode().getTokenValue()).isEqualTo(USER_CODE);

		ArgumentCaptor<OAuth2TokenContext> tokenContextCaptor = ArgumentCaptor.forClass(OAuth2TokenContext.class);
		verify(userCodeGenerator).generate(tokenContextCaptor.capture());
		verify(this.authorizationService).save(any(OAuth2Authorization.class));
		verifyNoMoreInteractions(this.authorizationService, userCodeGenerator);

		OAuth2TokenContext tokenContext = tokenContextCaptor.getValue();
		assertThat(tokenContext.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(tokenContext.<Authentication>getPrincipal()).isEqualTo(authentication.getPrincipal());
		assertThat(tokenContext.getAuthorizationServerContext()).isNotNull();
		assertThat(tokenContext.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.DEVICE_CODE);
		assertThat(tokenContext.<Authentication>getAuthorizationGrant()).isEqualTo(authentication);
		assertThat(tokenContext.getTokenType())
			.isEqualTo(OAuth2DeviceAuthorizationRequestAuthenticationProvider.USER_CODE_TOKEN_TYPE);
	}

	private static void mockAuthorizationServerContext() {
		AuthorizationServerSettings authorizationServerSettings = AuthorizationServerSettings.builder().build();
		TestAuthorizationServerContext authorizationServerContext = new TestAuthorizationServerContext(
				authorizationServerSettings, () -> "https://provider.com");
		AuthorizationServerContextHolder.setContext(authorizationServerContext);
	}

	private static OAuth2DeviceAuthorizationRequestAuthenticationToken createAuthentication(
			RegisteredClient registeredClient) {
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null);
		Set<String> requestedScopes = registeredClient.getScopes();
		if (requestedScopes.isEmpty()) {
			requestedScopes = null;
		}
		return new OAuth2DeviceAuthorizationRequestAuthenticationToken(clientPrincipal, AUTHORIZATION_URI,
				requestedScopes, null);
	}

	private static OAuth2DeviceCode createDeviceCode() {
		Instant issuedAt = Instant.now();
		return new OAuth2DeviceCode(DEVICE_CODE, issuedAt, issuedAt.plus(30, ChronoUnit.MINUTES));
	}

	private static OAuth2UserCode createUserCode() {
		Instant issuedAt = Instant.now();
		return new OAuth2UserCode(USER_CODE, issuedAt, issuedAt.plus(30, ChronoUnit.MINUTES));
	}

}
