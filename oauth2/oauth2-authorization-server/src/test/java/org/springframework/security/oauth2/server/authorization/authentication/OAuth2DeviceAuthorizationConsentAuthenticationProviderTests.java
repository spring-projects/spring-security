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

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests for {@link OAuth2DeviceAuthorizationConsentAuthenticationProvider}.
 *
 * @author Steve Riesenberg
 */
public class OAuth2DeviceAuthorizationConsentAuthenticationProviderTests {

	private static final String AUTHORIZATION_URI = "/oauth2/device_authorization";

	private static final String DEVICE_CODE = "EfYu_0jEL";

	private static final String USER_CODE = "BCDF-GHJK";

	private static final String STATE = "abc123";

	private RegisteredClientRepository registeredClientRepository;

	private OAuth2AuthorizationService authorizationService;

	private OAuth2AuthorizationConsentService authorizationConsentService;

	private OAuth2DeviceAuthorizationConsentAuthenticationProvider authenticationProvider;

	@BeforeEach
	public void setUp() {
		this.registeredClientRepository = mock(RegisteredClientRepository.class);
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.authorizationConsentService = mock(OAuth2AuthorizationConsentService.class);
		this.authenticationProvider = new OAuth2DeviceAuthorizationConsentAuthenticationProvider(
				this.registeredClientRepository, this.authorizationService, this.authorizationConsentService);
	}

	@Test
	public void constructorWhenRegisteredClientRepositoryIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2DeviceAuthorizationConsentAuthenticationProvider(
						null, this.authorizationService, this.authorizationConsentService))
				.withMessage("registeredClientRepository cannot be null");
		// @formatter:on
	}

	@Test
	public void constructorWhenAuthorizationServiceIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2DeviceAuthorizationConsentAuthenticationProvider(
						this.registeredClientRepository, null, this.authorizationConsentService))
				.withMessage("authorizationService cannot be null");
		// @formatter:on
	}

	@Test
	public void constructorWhenAuthorizationConsentServiceIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2DeviceAuthorizationConsentAuthenticationProvider(
						this.registeredClientRepository, this.authorizationService, null))
				.withMessage("authorizationConsentService cannot be null");
		// @formatter:on
	}

	@Test
	public void setAuthorizationConsentCustomizerWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authenticationProvider.setAuthorizationConsentCustomizer(null))
				.withMessageContaining("authorizationConsentCustomizer cannot be null");
		// @formatter:on
	}

	@Test
	public void supportsWhenTypeOAuth2DeviceAuthorizationConsentAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2DeviceAuthorizationConsentAuthenticationToken.class))
			.isTrue();
	}

	@Test
	public void authenticateWhenAuthorizationNotFoundThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		Authentication authentication = createAuthentication(registeredClient);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.withMessageContaining(OAuth2ParameterNames.STATE)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on

		verify(this.authorizationService).findByToken(STATE,
				OAuth2DeviceAuthorizationConsentAuthenticationProvider.STATE_TOKEN_TYPE);
		verifyNoInteractions(this.registeredClientRepository, this.authorizationConsentService);
	}

	@Test
	public void authenticateWhenPrincipalIsNotAuthenticatedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = createAuthorization(registeredClient);
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(authorization);
		TestingAuthenticationToken principal = new TestingAuthenticationToken(authorization.getPrincipalName(), null);
		Authentication authentication = new OAuth2DeviceAuthorizationConsentAuthenticationToken(AUTHORIZATION_URI,
				registeredClient.getClientId(), principal, USER_CODE, STATE, null, Collections.emptyMap());
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.withMessageContaining(OAuth2ParameterNames.STATE)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on

		verify(this.authorizationService).findByToken(STATE,
				OAuth2DeviceAuthorizationConsentAuthenticationProvider.STATE_TOKEN_TYPE);
		verifyNoInteractions(this.registeredClientRepository, this.authorizationConsentService);
	}

	@Test
	public void authenticateWhenPrincipalNameDoesNotMatchThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = createAuthorization(registeredClient);
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(authorization);
		TestingAuthenticationToken principal = new TestingAuthenticationToken("invalid", null, Collections.emptyList());
		Authentication authentication = new OAuth2DeviceAuthorizationConsentAuthenticationToken(AUTHORIZATION_URI,
				registeredClient.getClientId(), principal, USER_CODE, STATE, null, Collections.emptyMap());
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.withMessageContaining(OAuth2ParameterNames.STATE)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on

		verify(this.authorizationService).findByToken(STATE,
				OAuth2DeviceAuthorizationConsentAuthenticationProvider.STATE_TOKEN_TYPE);
		verifyNoInteractions(this.registeredClientRepository, this.authorizationConsentService);
	}

	@Test
	public void authenticateWhenRegisteredClientNotFoundThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = createAuthorization(registeredClient);
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(authorization);
		Authentication authentication = createAuthentication(registeredClient);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.withMessageContaining(OAuth2ParameterNames.CLIENT_ID)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on

		verify(this.registeredClientRepository).findByClientId(registeredClient.getClientId());
		verify(this.authorizationService).findByToken(STATE,
				OAuth2DeviceAuthorizationConsentAuthenticationProvider.STATE_TOKEN_TYPE);
		verifyNoMoreInteractions(this.registeredClientRepository, this.authorizationService);
		verifyNoInteractions(this.authorizationConsentService);
	}

	@Test
	public void authenticateWhenRegisteredClientDoesNotMatchAuthorizationThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		RegisteredClient registeredClient2 = TestRegisteredClients.registeredClient2().build();
		OAuth2Authorization authorization = createAuthorization(registeredClient2);
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(authorization);
		given(this.registeredClientRepository.findByClientId(anyString())).willReturn(registeredClient);
		Authentication authentication = createAuthentication(registeredClient);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.withMessageContaining(OAuth2ParameterNames.CLIENT_ID)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on

		verify(this.registeredClientRepository).findByClientId(registeredClient.getClientId());
		verify(this.authorizationService).findByToken(STATE,
				OAuth2DeviceAuthorizationConsentAuthenticationProvider.STATE_TOKEN_TYPE);
		verifyNoMoreInteractions(this.registeredClientRepository, this.authorizationService);
		verifyNoInteractions(this.authorizationConsentService);
	}

	@Test
	public void authenticateWhenRequestedScopesNotAuthorizedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		RegisteredClient registeredClient2 = TestRegisteredClients.registeredClient()
			.scopes(Set::clear)
			.scope("invalid")
			.build();
		OAuth2Authorization authorization = createAuthorization(registeredClient);
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(authorization);
		given(this.registeredClientRepository.findByClientId(anyString())).willReturn(registeredClient);
		Authentication authentication = createAuthentication(registeredClient2);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.withMessageContaining(OAuth2ParameterNames.SCOPE)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE);
		// @formatter:on

		verify(this.registeredClientRepository).findByClientId(registeredClient.getClientId());
		verify(this.authorizationService).findByToken(STATE,
				OAuth2DeviceAuthorizationConsentAuthenticationProvider.STATE_TOKEN_TYPE);
		verifyNoMoreInteractions(this.registeredClientRepository, this.authorizationService);
		verifyNoInteractions(this.authorizationConsentService);
	}

	@Test
	public void authenticateWhenAuthoritiesIsEmptyThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		RegisteredClient registeredClient2 = TestRegisteredClients.registeredClient().scopes(Set::clear).build();
		OAuth2Authorization authorization = createAuthorization(registeredClient2);
		Authentication authentication = createAuthentication(registeredClient2);
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(authorization);
		given(this.registeredClientRepository.findByClientId(anyString())).willReturn(registeredClient);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.ACCESS_DENIED);
		// @formatter:on

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).findByToken(STATE,
				OAuth2DeviceAuthorizationConsentAuthenticationProvider.STATE_TOKEN_TYPE);
		verify(this.registeredClientRepository).findByClientId(registeredClient.getClientId());
		verify(this.authorizationConsentService).findById(registeredClient.getId(), authentication.getName());
		verify(this.authorizationService).save(authorizationCaptor.capture());
		verifyNoMoreInteractions(this.registeredClientRepository, this.authorizationService,
				this.authorizationConsentService);

		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();
		assertThat(updatedAuthorization.<String>getAttribute(OAuth2ParameterNames.STATE)).isNull();
		// @formatter:off
		assertThat(updatedAuthorization.getToken(OAuth2DeviceCode.class))
				.extracting(isInvalidated())
				.isEqualTo(true);
		assertThat(updatedAuthorization.getToken(OAuth2UserCode.class))
				.extracting(isInvalidated())
				.isEqualTo(true);
		// @formatter:on
	}

	@Test
	public void authenticateWhenAuthoritiesIsNotEmptyThenAuthorizationConsentSaved() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = createAuthorization(registeredClient);
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(authorization);
		given(this.registeredClientRepository.findByClientId(anyString())).willReturn(registeredClient);

		Authentication authentication = createAuthentication(registeredClient);
		OAuth2DeviceVerificationAuthenticationToken authenticationResult = (OAuth2DeviceVerificationAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);
		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.getClientId()).isEqualTo(registeredClient.getClientId());
		assertThat(authenticationResult.getPrincipal()).isSameAs(authentication.getPrincipal());
		assertThat(authenticationResult.getUserCode()).isEqualTo(USER_CODE);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).findByToken(STATE,
				OAuth2DeviceAuthorizationConsentAuthenticationProvider.STATE_TOKEN_TYPE);
		verify(this.registeredClientRepository).findByClientId(registeredClient.getClientId());
		verify(this.authorizationConsentService).findById(registeredClient.getId(), authentication.getName());
		verify(this.authorizationConsentService).save(any(OAuth2AuthorizationConsent.class));
		verify(this.authorizationService).save(authorizationCaptor.capture());
		verifyNoMoreInteractions(this.registeredClientRepository, this.authorizationService,
				this.authorizationConsentService);

		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();
		assertThat(updatedAuthorization.getPrincipalName()).isEqualTo(authentication.getName());
		assertThat(updatedAuthorization.getAuthorizedScopes()).hasSameElementsAs(registeredClient.getScopes());
		assertThat(updatedAuthorization.<String>getAttribute(OAuth2ParameterNames.STATE)).isNull();
		assertThat(updatedAuthorization.<Set<String>>getAttribute(OAuth2ParameterNames.SCOPE)).isNull();
		// @formatter:off
		assertThat(updatedAuthorization.getToken(OAuth2DeviceCode.class))
				.extracting(isInvalidated())
				.isEqualTo(false);
		assertThat(updatedAuthorization.getToken(OAuth2UserCode.class))
				.extracting(isInvalidated())
				.isEqualTo(true);
		// @formatter:on
	}

	@Test
	public void authenticateWhenExistingAuthorizationConsentThenUpdated() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scope("additional").build();
		RegisteredClient registeredClient2 = TestRegisteredClients.registeredClient()
			.scopes(Set::clear)
			.scope("additional")
			.build();
		OAuth2Authorization authorization = createAuthorization(registeredClient2);
		Authentication authentication = createAuthentication(registeredClient2);
		// @formatter:off
		OAuth2AuthorizationConsent authorizationConsent =
				OAuth2AuthorizationConsent.withId(registeredClient.getId(), authentication.getName())
						.scope("scope1").build();
		// @formatter:on
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(authorization);
		given(this.registeredClientRepository.findByClientId(anyString())).willReturn(registeredClient);
		given(this.authorizationConsentService.findById(anyString(), anyString())).willReturn(authorizationConsent);

		OAuth2DeviceVerificationAuthenticationToken authenticationResult = (OAuth2DeviceVerificationAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);
		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.getClientId()).isEqualTo(registeredClient.getClientId());
		assertThat(authenticationResult.getPrincipal()).isSameAs(authentication.getPrincipal());
		assertThat(authenticationResult.getUserCode()).isEqualTo(USER_CODE);

		ArgumentCaptor<OAuth2AuthorizationConsent> authorizationConsentCaptor = ArgumentCaptor
			.forClass(OAuth2AuthorizationConsent.class);
		verify(this.authorizationService).findByToken(STATE,
				OAuth2DeviceAuthorizationConsentAuthenticationProvider.STATE_TOKEN_TYPE);
		verify(this.registeredClientRepository).findByClientId(registeredClient.getClientId());
		verify(this.authorizationConsentService).findById(registeredClient.getId(), authentication.getName());
		verify(this.authorizationConsentService).save(authorizationConsentCaptor.capture());
		verify(this.authorizationService).save(any(OAuth2Authorization.class));
		verifyNoMoreInteractions(this.registeredClientRepository, this.authorizationService,
				this.authorizationConsentService);

		OAuth2AuthorizationConsent updatedAuthorizationConsent = authorizationConsentCaptor.getValue();
		assertThat(updatedAuthorizationConsent.getRegisteredClientId()).isEqualTo(registeredClient.getId());
		assertThat(updatedAuthorizationConsent.getPrincipalName()).isEqualTo(authentication.getName());
		assertThat(updatedAuthorizationConsent.getScopes()).hasSameElementsAs(registeredClient.getScopes());
	}

	@Test
	public void authenticateWhenAuthorizationConsentCustomizerSetThenUsed() {
		SimpleGrantedAuthority customAuthority = new SimpleGrantedAuthority("test");
		this.authenticationProvider.setAuthorizationConsentCustomizer(
				(context) -> context.getAuthorizationConsent().authority(customAuthority));

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scopes(Set::clear).build();
		OAuth2Authorization authorization = createAuthorization(registeredClient);
		Authentication authentication = createAuthentication(registeredClient);
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(authorization);
		given(this.registeredClientRepository.findByClientId(anyString())).willReturn(registeredClient);
		given(this.authorizationConsentService.findById(anyString(), anyString())).willReturn(null);

		OAuth2DeviceVerificationAuthenticationToken authenticationResult = (OAuth2DeviceVerificationAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);
		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.getClientId()).isEqualTo(registeredClient.getClientId());
		assertThat(authenticationResult.getPrincipal()).isSameAs(authentication.getPrincipal());
		assertThat(authenticationResult.getUserCode()).isEqualTo(USER_CODE);

		ArgumentCaptor<OAuth2AuthorizationConsent> authorizationConsentCaptor = ArgumentCaptor
			.forClass(OAuth2AuthorizationConsent.class);
		verify(this.authorizationService).findByToken(STATE,
				OAuth2DeviceAuthorizationConsentAuthenticationProvider.STATE_TOKEN_TYPE);
		verify(this.registeredClientRepository).findByClientId(registeredClient.getClientId());
		verify(this.authorizationConsentService).findById(registeredClient.getId(), authentication.getName());
		verify(this.authorizationConsentService).save(authorizationConsentCaptor.capture());
		verify(this.authorizationService).save(any(OAuth2Authorization.class));
		verifyNoMoreInteractions(this.registeredClientRepository, this.authorizationService,
				this.authorizationConsentService);

		OAuth2AuthorizationConsent updatedAuthorizationConsent = authorizationConsentCaptor.getValue();
		assertThat(updatedAuthorizationConsent.getRegisteredClientId()).isEqualTo(registeredClient.getId());
		assertThat(updatedAuthorizationConsent.getPrincipalName()).isEqualTo(authentication.getName());
		assertThat(updatedAuthorizationConsent.getAuthorities()).containsExactly(customAuthority);
	}

	private static OAuth2Authorization createAuthorization(RegisteredClient registeredClient) {
		// @formatter:off
		return TestOAuth2Authorizations.authorization(registeredClient)
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.token(createDeviceCode())
				.token(createUserCode())
				.attributes(Map::clear)
				.attribute(OAuth2ParameterNames.SCOPE, registeredClient.getScopes())
				.build();
		// @formatter:on
	}

	private static OAuth2DeviceAuthorizationConsentAuthenticationToken createAuthentication(
			RegisteredClient registeredClient) {
		TestingAuthenticationToken principal = new TestingAuthenticationToken("principal", null,
				Collections.emptyList());
		Set<String> authorizedScopes = registeredClient.getScopes();
		if (authorizedScopes.isEmpty()) {
			authorizedScopes = null;
		}
		Map<String, Object> additionalParameters = null;
		return new OAuth2DeviceAuthorizationConsentAuthenticationToken(AUTHORIZATION_URI,
				registeredClient.getClientId(), principal, USER_CODE, STATE, authorizedScopes, additionalParameters);
	}

	private static OAuth2DeviceCode createDeviceCode() {
		Instant issuedAt = Instant.now();
		return new OAuth2DeviceCode(DEVICE_CODE, issuedAt, issuedAt.plus(30, ChronoUnit.MINUTES));
	}

	private static OAuth2UserCode createUserCode() {
		Instant issuedAt = Instant.now();
		return new OAuth2UserCode(USER_CODE, issuedAt, issuedAt.plus(30, ChronoUnit.MINUTES));
	}

	private static Function<OAuth2Authorization.Token<? extends OAuth2Token>, Boolean> isInvalidated() {
		return (token) -> token.getMetadata(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME);
	}

}
