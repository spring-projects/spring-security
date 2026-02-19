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

import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
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
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.context.TestAuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests for {@link OAuth2DeviceVerificationAuthenticationProvider}.
 *
 * @author Steve Riesenberg
 */
public class OAuth2DeviceVerificationAuthenticationProviderTests {

	private static final String AUTHORIZATION_URI = "/oauth2/device_verification";

	private static final String DEVICE_CODE = "EfYu_0jEL";

	private static final String USER_CODE = "BCDF-GHJK";

	private RegisteredClientRepository registeredClientRepository;

	private OAuth2AuthorizationService authorizationService;

	private OAuth2AuthorizationConsentService authorizationConsentService;

	private OAuth2DeviceVerificationAuthenticationProvider authenticationProvider;

	@BeforeEach
	public void setUp() {
		this.registeredClientRepository = mock(RegisteredClientRepository.class);
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.authorizationConsentService = mock(OAuth2AuthorizationConsentService.class);
		this.authenticationProvider = new OAuth2DeviceVerificationAuthenticationProvider(
				this.registeredClientRepository, this.authorizationService, this.authorizationConsentService);
		mockAuthorizationServerContext();
	}

	@AfterEach
	public void tearDown() {
		AuthorizationServerContextHolder.resetContext();
	}

	@Test
	public void constructorWhenRegisteredClientRepositoryIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2DeviceVerificationAuthenticationProvider(
						null, this.authorizationService, this.authorizationConsentService))
				.withMessage("registeredClientRepository cannot be null");
		// @formatter:on
	}

	@Test
	public void constructorWhenAuthorizationServiceIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2DeviceVerificationAuthenticationProvider(
						this.registeredClientRepository, null, this.authorizationConsentService))
				.withMessage("authorizationService cannot be null");
		// @formatter:on
	}

	@Test
	public void constructorWhenAuthorizationConsentServiceIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2DeviceVerificationAuthenticationProvider(
						this.registeredClientRepository, this.authorizationService, null))
				.withMessage("authorizationConsentService cannot be null");
		// @formatter:on
	}

	@Test
	public void setAuthorizationConsentRequiredWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.authenticationProvider.setAuthorizationConsentRequired(null))
			.withMessage("authorizationConsentRequired cannot be null");
	}

	@Test
	public void supportsWhenTypeOAuth2DeviceVerificationAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2DeviceVerificationAuthenticationToken.class)).isTrue();
	}

	@Test
	public void authenticateWhenAuthorizationNotFoundThenThrowOAuth2AuthenticationException() {
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(null);
		Authentication authentication = createAuthentication();
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
		// @formatter:on

		verify(this.authorizationService).findByToken(USER_CODE,
				OAuth2DeviceVerificationAuthenticationProvider.USER_CODE_TOKEN_TYPE);
		verifyNoMoreInteractions(this.authorizationService);
		verifyNoInteractions(this.registeredClientRepository, this.authorizationConsentService);
	}

	@Test
	public void authenticateWhenUserCodeIsInvalidatedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		// @formatter:off
		OAuth2Authorization authorization = TestOAuth2Authorizations
				.authorization(registeredClient)
				.token(createDeviceCode())
				.token(createUserCode(), withInvalidated())
				.attribute(OAuth2ParameterNames.SCOPE, registeredClient.getScopes())
				.build();
		// @formatter:on
		given(this.authorizationService.findByToken(eq(USER_CODE),
				eq(OAuth2DeviceVerificationAuthenticationProvider.USER_CODE_TOKEN_TYPE)))
			.willReturn(authorization);
		Authentication authentication = createAuthentication();
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
		// @formatter:on

		verify(this.authorizationService).findByToken(USER_CODE,
				OAuth2DeviceVerificationAuthenticationProvider.USER_CODE_TOKEN_TYPE);
		verifyNoMoreInteractions(this.authorizationService);
		verifyNoInteractions(this.registeredClientRepository, this.authorizationConsentService);
	}

	@Test
	public void authenticateWhenUserCodeIsExpiredAndNotInvalidatedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		// @formatter:off
		OAuth2Authorization authorization = TestOAuth2Authorizations
				.authorization(registeredClient)
				// Device code would also be expired but not relevant for this test
				.token(createDeviceCode())
				.token(createExpiredUserCode())
				.attribute(OAuth2ParameterNames.SCOPE, registeredClient.getScopes())
				.build();
		// @formatter:on
		given(this.authorizationService.findByToken(eq(USER_CODE),
				eq(OAuth2DeviceVerificationAuthenticationProvider.USER_CODE_TOKEN_TYPE)))
			.willReturn(authorization);
		Authentication authentication = createAuthentication();
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
		// @formatter:on

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).findByToken(USER_CODE,
				OAuth2DeviceVerificationAuthenticationProvider.USER_CODE_TOKEN_TYPE);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		verifyNoMoreInteractions(this.authorizationService);
		verifyNoInteractions(this.registeredClientRepository, this.authorizationConsentService);

		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();
		assertThat(updatedAuthorization.getToken(OAuth2UserCode.class)).extracting(isInvalidated()).isEqualTo(true);
	}

	@Test
	public void authenticateWhenPrincipalNotAuthenticatedThenReturnUnauthenticated() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		// @formatter:off
		OAuth2Authorization authorization = TestOAuth2Authorizations
				.authorization(registeredClient)
				.token(createDeviceCode())
				.token(createUserCode())
				.attribute(OAuth2ParameterNames.SCOPE, registeredClient.getScopes())
				.build();
		// @formatter:on
		TestingAuthenticationToken principal = new TestingAuthenticationToken("user", null);
		Authentication authentication = new OAuth2DeviceVerificationAuthenticationToken(principal, USER_CODE,
				Collections.emptyMap());
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(authorization);

		OAuth2DeviceVerificationAuthenticationToken authenticationResult = (OAuth2DeviceVerificationAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);
		assertThat(authenticationResult).isEqualTo(authentication);
		assertThat(authenticationResult.isAuthenticated()).isFalse();

		verify(this.authorizationService).findByToken(USER_CODE,
				OAuth2DeviceVerificationAuthenticationProvider.USER_CODE_TOKEN_TYPE);
		verifyNoMoreInteractions(this.authorizationService);
		verifyNoInteractions(this.registeredClientRepository, this.authorizationConsentService);
	}

	@Test
	public void authenticateWhenAuthorizationConsentDoesNotExistThenReturnAuthorizationConsentWithState() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		// @formatter:off
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.token(createDeviceCode())
				.token(createUserCode())
				.attribute(OAuth2ParameterNames.SCOPE, registeredClient.getScopes())
				.build();
		// @formatter:on
		Authentication authentication = createAuthentication();
		given(this.registeredClientRepository.findById(anyString())).willReturn(registeredClient);
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(authorization);
		given(this.authorizationConsentService.findById(anyString(), anyString())).willReturn(null);

		OAuth2DeviceAuthorizationConsentAuthenticationToken authenticationResult = (OAuth2DeviceAuthorizationConsentAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);
		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.getAuthorizationUri()).isEqualTo(AUTHORIZATION_URI);
		assertThat(authenticationResult.getClientId()).isEqualTo(registeredClient.getClientId());
		assertThat(authenticationResult.getPrincipal()).isEqualTo(authentication.getPrincipal());
		assertThat(authenticationResult.getUserCode()).isEqualTo(USER_CODE);
		assertThat(authenticationResult.getState()).hasSize(44);
		assertThat(authenticationResult.getRequestedScopes()).hasSameElementsAs(registeredClient.getScopes());
		assertThat(authenticationResult.getScopes()).isEmpty();

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).findByToken(USER_CODE,
				OAuth2DeviceVerificationAuthenticationProvider.USER_CODE_TOKEN_TYPE);
		verify(this.registeredClientRepository).findById(authorization.getRegisteredClientId());
		verify(this.authorizationService).save(authorizationCaptor.capture());
		verify(this.authorizationConsentService).findById(registeredClient.getId(), authentication.getName());
		verifyNoMoreInteractions(this.registeredClientRepository, this.authorizationService,
				this.authorizationConsentService);

		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();
		assertThat(updatedAuthorization.<String>getAttribute(OAuth2ParameterNames.STATE))
			.isEqualTo(authenticationResult.getState());
	}

	@Test
	public void authenticateWhenAuthorizationConsentExistsAndRequestedScopesMatchThenReturnDeviceVerification() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		// @formatter:off
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.token(createDeviceCode())
				.token(createUserCode())
				.attributes(Map::clear)
				.attribute(OAuth2ParameterNames.SCOPE, registeredClient.getScopes())
				.build();
		// @formatter:on
		Authentication authentication = createAuthentication();
		// @formatter:off
		OAuth2AuthorizationConsent authorizationConsent =
				OAuth2AuthorizationConsent.withId(registeredClient.getId(), authentication.getName())
						.scope(registeredClient.getScopes().iterator().next())
						.build();
		// @formatter:on
		given(this.registeredClientRepository.findById(anyString())).willReturn(registeredClient);
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(authorization);
		given(this.authorizationConsentService.findById(anyString(), anyString())).willReturn(authorizationConsent);

		OAuth2DeviceVerificationAuthenticationToken authenticationResult = (OAuth2DeviceVerificationAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);
		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.getClientId()).isEqualTo(registeredClient.getClientId());
		assertThat(authenticationResult.getPrincipal()).isEqualTo(authentication.getPrincipal());
		assertThat(authenticationResult.getUserCode()).isEqualTo(USER_CODE);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).findByToken(USER_CODE,
				OAuth2DeviceVerificationAuthenticationProvider.USER_CODE_TOKEN_TYPE);
		verify(this.registeredClientRepository).findById(authorization.getRegisteredClientId());
		verify(this.authorizationService).save(authorizationCaptor.capture());
		verify(this.authorizationConsentService).findById(registeredClient.getId(), authentication.getName());
		verifyNoMoreInteractions(this.registeredClientRepository, this.authorizationService,
				this.authorizationConsentService);

		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();
		assertThat(updatedAuthorization.getPrincipalName()).isEqualTo(authentication.getName());
		assertThat(updatedAuthorization.getAuthorizedScopes()).hasSameElementsAs(registeredClient.getScopes());
		assertThat(updatedAuthorization.<Authentication>getAttribute(Principal.class.getName()))
			.isEqualTo(authentication.getPrincipal());
		assertThat(updatedAuthorization.<String>getAttribute(OAuth2ParameterNames.STATE)).isNull();
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
	public void authenticateWhenAuthorizationConsentExistsAndRequestedScopesDoNotMatchThenReturnAuthorizationConsentWithState() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		// @formatter:off
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.token(createDeviceCode())
				.token(createUserCode())
				.attributes(Map::clear)
				.attribute(OAuth2ParameterNames.SCOPE, registeredClient.getScopes())
				.build();
		// @formatter:on
		Authentication authentication = createAuthentication();
		// @formatter:off
		OAuth2AuthorizationConsent authorizationConsent =
				OAuth2AuthorizationConsent.withId(registeredClient.getId(), authentication.getName())
						.scope("previous")
						.build();
		// @formatter:on
		given(this.registeredClientRepository.findById(anyString())).willReturn(registeredClient);
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(authorization);
		given(this.authorizationConsentService.findById(anyString(), anyString())).willReturn(authorizationConsent);

		OAuth2DeviceAuthorizationConsentAuthenticationToken authenticationResult = (OAuth2DeviceAuthorizationConsentAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);
		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.getAuthorizationUri()).isEqualTo(AUTHORIZATION_URI);
		assertThat(authenticationResult.getClientId()).isEqualTo(registeredClient.getClientId());
		assertThat(authenticationResult.getPrincipal()).isEqualTo(authentication.getPrincipal());
		assertThat(authenticationResult.getUserCode()).isEqualTo(USER_CODE);
		assertThat(authenticationResult.getState()).hasSize(44);
		assertThat(authenticationResult.getRequestedScopes()).hasSameElementsAs(registeredClient.getScopes());
		assertThat(authenticationResult.getScopes()).containsExactly("previous");

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).findByToken(USER_CODE,
				OAuth2DeviceVerificationAuthenticationProvider.USER_CODE_TOKEN_TYPE);
		verify(this.registeredClientRepository).findById(authorization.getRegisteredClientId());
		verify(this.authorizationService).save(authorizationCaptor.capture());
		verify(this.authorizationConsentService).findById(registeredClient.getId(), authentication.getName());
		verifyNoMoreInteractions(this.registeredClientRepository, this.authorizationService,
				this.authorizationConsentService);

		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();
		assertThat(updatedAuthorization.<String>getAttribute(OAuth2ParameterNames.STATE))
			.isEqualTo(authenticationResult.getState());
	}

	@Test
	public void authenticateWhenCustomAuthorizationConsentRequiredThenUsed() {
		@SuppressWarnings("unchecked")
		Predicate<OAuth2DeviceVerificationAuthenticationContext> authorizationConsentRequired = mock(Predicate.class);
		this.authenticationProvider.setAuthorizationConsentRequired(authorizationConsentRequired);

		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.token(createDeviceCode())
				.token(createUserCode())
				.attributes(Map::clear)
				.attribute(OAuth2ParameterNames.SCOPE, registeredClient.getScopes())
				.build();
		// @formatter:on
		Authentication authentication = createAuthentication();
		given(this.registeredClientRepository.findById(anyString())).willReturn(registeredClient);
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(authorization);

		this.authenticationProvider.authenticate(authentication);

		verify(authorizationConsentRequired).test(any());
	}

	private static void mockAuthorizationServerContext() {
		AuthorizationServerSettings authorizationServerSettings = AuthorizationServerSettings.builder().build();
		TestAuthorizationServerContext authorizationServerContext = new TestAuthorizationServerContext(
				authorizationServerSettings, () -> "https://provider.com");
		AuthorizationServerContextHolder.setContext(authorizationServerContext);
	}

	private static OAuth2DeviceVerificationAuthenticationToken createAuthentication() {
		TestingAuthenticationToken principal = new TestingAuthenticationToken("user", null,
				AuthorityUtils.createAuthorityList("USER"));
		return new OAuth2DeviceVerificationAuthenticationToken(principal, USER_CODE, Collections.emptyMap());
	}

	private static OAuth2DeviceCode createDeviceCode() {
		Instant issuedAt = Instant.now();
		return new OAuth2DeviceCode(DEVICE_CODE, issuedAt, issuedAt.plus(30, ChronoUnit.MINUTES));
	}

	private static OAuth2UserCode createUserCode() {
		Instant issuedAt = Instant.now();
		return new OAuth2UserCode(USER_CODE, issuedAt, issuedAt.plus(30, ChronoUnit.MINUTES));
	}

	private static OAuth2UserCode createExpiredUserCode() {
		Instant issuedAt = Instant.now().minus(45, ChronoUnit.MINUTES);
		return new OAuth2UserCode(USER_CODE, issuedAt, issuedAt.plus(30, ChronoUnit.MINUTES));
	}

	private static Consumer<Map<String, Object>> withInvalidated() {
		return (metadata) -> metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true);
	}

	private static Function<OAuth2Authorization.Token<? extends OAuth2Token>, Boolean> isInvalidated() {
		return (token) -> token.getMetadata(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME);
	}

}
