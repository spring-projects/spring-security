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
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link OAuth2AuthorizationConsentAuthenticationProvider}.
 *
 * @author Joe Grandja
 * @author Steve Riesenberg
 */
public class OAuth2AuthorizationConsentAuthenticationProviderTests {

	private static final String AUTHORIZATION_URI = "https://provider.com/oauth2/authorize";

	private static final String STATE = "state";

	private static final OAuth2TokenType STATE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.STATE);

	private RegisteredClientRepository registeredClientRepository;

	private OAuth2AuthorizationService authorizationService;

	private OAuth2AuthorizationConsentService authorizationConsentService;

	private OAuth2AuthorizationConsentAuthenticationProvider authenticationProvider;

	private TestingAuthenticationToken principal;

	@BeforeEach
	public void setUp() {
		this.registeredClientRepository = mock(RegisteredClientRepository.class);
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.authorizationConsentService = mock(OAuth2AuthorizationConsentService.class);
		this.authenticationProvider = new OAuth2AuthorizationConsentAuthenticationProvider(
				this.registeredClientRepository, this.authorizationService, this.authorizationConsentService);
		this.principal = new TestingAuthenticationToken("principalName", "password");
		this.principal.setAuthenticated(true);
		AuthorizationServerSettings authorizationServerSettings = AuthorizationServerSettings.builder()
			.issuer("https://provider.com")
			.build();
		AuthorizationServerContextHolder
			.setContext(new TestAuthorizationServerContext(authorizationServerSettings, null));
	}

	@AfterEach
	public void tearDown() {
		AuthorizationServerContextHolder.resetContext();
	}

	@Test
	public void constructorWhenRegisteredClientRepositoryNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> new OAuth2AuthorizationConsentAuthenticationProvider(null, this.authorizationService,
					this.authorizationConsentService))
			.withMessage("registeredClientRepository cannot be null");
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> new OAuth2AuthorizationConsentAuthenticationProvider(this.registeredClientRepository,
					null, this.authorizationConsentService))
			.withMessage("authorizationService cannot be null");
	}

	@Test
	public void constructorWhenAuthorizationConsentServiceNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> new OAuth2AuthorizationConsentAuthenticationProvider(this.registeredClientRepository,
					this.authorizationService, null))
			.withMessage("authorizationConsentService cannot be null");
	}

	@Test
	public void supportsWhenTypeOAuth2AuthorizationConsentAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2AuthorizationConsentAuthenticationToken.class)).isTrue();
	}

	@Test
	public void setAuthorizationCodeGeneratorWhenNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.authenticationProvider.setAuthorizationCodeGenerator(null))
			.withMessage("authorizationCodeGenerator cannot be null");
	}

	@Test
	public void setAuthorizationConsentCustomizerWhenNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.authenticationProvider.setAuthorizationConsentCustomizer(null))
			.withMessage("authorizationConsentCustomizer cannot be null");
	}

	@Test
	public void authenticateWhenInvalidStateThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2AuthorizationConsentAuthenticationToken authentication = new OAuth2AuthorizationConsentAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, STATE, registeredClient.getScopes(),
				null);
		given(this.authorizationService.findByToken(eq(authentication.getState()), eq(STATE_TOKEN_TYPE)))
			.willReturn(null);

		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.satisfies((ex) -> assertAuthenticationException(ex, OAuth2ErrorCodes.INVALID_REQUEST,
					OAuth2ParameterNames.STATE, null));
	}

	@Test
	public void authenticateWhenPrincipalNotAuthenticatedThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.principalName(this.principal.getName())
			.build();
		OAuth2AuthorizationConsentAuthenticationToken authentication = new OAuth2AuthorizationConsentAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, STATE, registeredClient.getScopes(),
				null);
		given(this.authorizationService.findByToken(eq(authentication.getState()), eq(STATE_TOKEN_TYPE)))
			.willReturn(authorization);
		this.principal.setAuthenticated(false);

		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.satisfies((ex) -> assertAuthenticationException(ex, OAuth2ErrorCodes.INVALID_REQUEST,
					OAuth2ParameterNames.STATE, null));
	}

	@Test
	public void authenticateWhenInvalidPrincipalThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.principalName(this.principal.getName().concat("-other"))
			.build();
		OAuth2AuthorizationConsentAuthenticationToken authentication = new OAuth2AuthorizationConsentAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, STATE, registeredClient.getScopes(),
				null);
		given(this.authorizationService.findByToken(eq(authentication.getState()), eq(STATE_TOKEN_TYPE)))
			.willReturn(authorization);

		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.satisfies((ex) -> assertAuthenticationException(ex, OAuth2ErrorCodes.INVALID_REQUEST,
					OAuth2ParameterNames.STATE, null));
	}

	@Test
	public void authenticateWhenInvalidClientIdThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.principalName(this.principal.getName())
			.build();
		given(this.authorizationService.findByToken(eq("state"), eq(STATE_TOKEN_TYPE))).willReturn(authorization);
		RegisteredClient otherRegisteredClient = TestRegisteredClients.registeredClient2().build();
		OAuth2AuthorizationConsentAuthenticationToken authentication = new OAuth2AuthorizationConsentAuthenticationToken(
				AUTHORIZATION_URI, otherRegisteredClient.getClientId(), this.principal, STATE,
				registeredClient.getScopes(), null);

		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.satisfies((ex) -> assertAuthenticationException(ex, OAuth2ErrorCodes.INVALID_REQUEST,
					OAuth2ParameterNames.CLIENT_ID, null));
	}

	@Test
	public void authenticateWhenDoesNotMatchClientThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);
		RegisteredClient otherRegisteredClient = TestRegisteredClients.registeredClient2().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(otherRegisteredClient)
			.principalName(this.principal.getName())
			.build();
		given(this.authorizationService.findByToken(eq("state"), eq(STATE_TOKEN_TYPE))).willReturn(authorization);
		OAuth2AuthorizationConsentAuthenticationToken authentication = new OAuth2AuthorizationConsentAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, STATE, registeredClient.getScopes(),
				null);

		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.satisfies((ex) -> assertAuthenticationException(ex, OAuth2ErrorCodes.INVALID_REQUEST,
					OAuth2ParameterNames.CLIENT_ID, null));
	}

	@Test
	public void authenticateWhenScopeNotRequestedThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.principalName(this.principal.getName())
			.build();
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		Set<String> authorizedScopes = new HashSet<>(authorizationRequest.getScopes());
		authorizedScopes.add("scope-not-requested");
		OAuth2AuthorizationConsentAuthenticationToken authentication = new OAuth2AuthorizationConsentAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, STATE, authorizedScopes, null);
		given(this.authorizationService.findByToken(eq(authentication.getState()), eq(STATE_TOKEN_TYPE)))
			.willReturn(authorization);

		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.satisfies((ex) -> assertAuthenticationException(ex, OAuth2ErrorCodes.INVALID_SCOPE,
					OAuth2ParameterNames.SCOPE, authorizationRequest.getRedirectUri()));
	}

	@Test
	public void authenticateWhenNotApprovedThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.principalName(this.principal.getName())
			.build();
		OAuth2AuthorizationConsentAuthenticationToken authentication = new OAuth2AuthorizationConsentAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, STATE, new HashSet<>(), null); // No
																													// scopes
																													// approved
		given(this.authorizationService.findByToken(eq(authentication.getState()), eq(STATE_TOKEN_TYPE)))
			.willReturn(authorization);

		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());

		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.satisfies((ex) -> assertAuthenticationException(ex, OAuth2ErrorCodes.ACCESS_DENIED,
					OAuth2ParameterNames.CLIENT_ID, authorizationRequest.getRedirectUri()));

		verify(this.authorizationService).remove(eq(authorization));
	}

	@Test
	public void authenticateWhenApproveAllThenReturnAuthorizationCode() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.principalName(this.principal.getName())
			.build();
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		Set<String> authorizedScopes = authorizationRequest.getScopes();
		OAuth2AuthorizationConsentAuthenticationToken authentication = new OAuth2AuthorizationConsentAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, STATE, authorizedScopes, null); // Approve
																													// all
																													// scopes
		given(this.authorizationService.findByToken(eq(authentication.getState()), eq(STATE_TOKEN_TYPE)))
			.willReturn(authorization);

		OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult = (OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		assertAuthorizationConsentRequestWithAuthorizationCodeResult(registeredClient, authorization,
				authenticationResult);
	}

	@Test
	public void authenticateWhenCustomAuthorizationConsentCustomizerThenUsed() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.principalName(this.principal.getName())
			.build();
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		Set<String> authorizedScopes = authorizationRequest.getScopes();
		OAuth2AuthorizationConsentAuthenticationToken authentication = new OAuth2AuthorizationConsentAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, STATE, authorizedScopes, null); // Approve
																													// all
																													// scopes
		given(this.authorizationService.findByToken(eq(authentication.getState()), eq(STATE_TOKEN_TYPE)))
			.willReturn(authorization);

		@SuppressWarnings("unchecked")
		Consumer<OAuth2AuthorizationConsentAuthenticationContext> authorizationConsentCustomizer = mock(Consumer.class);
		this.authenticationProvider.setAuthorizationConsentCustomizer(authorizationConsentCustomizer);

		OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult = (OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		assertAuthorizationConsentRequestWithAuthorizationCodeResult(registeredClient, authorization,
				authenticationResult);

		ArgumentCaptor<OAuth2AuthorizationConsentAuthenticationContext> authenticationContextCaptor = ArgumentCaptor
			.forClass(OAuth2AuthorizationConsentAuthenticationContext.class);
		verify(authorizationConsentCustomizer).accept(authenticationContextCaptor.capture());

		OAuth2AuthorizationConsentAuthenticationContext authenticationContext = authenticationContextCaptor.getValue();
		assertThat(authenticationContext.<Authentication>getAuthentication()).isEqualTo(authentication);
		assertThat(authenticationContext.getAuthorizationConsent()).isNotNull();
		assertThat(authenticationContext.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(authenticationContext.getAuthorization()).isEqualTo(authorization);
		assertThat(authenticationContext.getAuthorizationRequest()).isEqualTo(authorizationRequest);
	}

	private void assertAuthorizationConsentRequestWithAuthorizationCodeResult(RegisteredClient registeredClient,
			OAuth2Authorization authorization, OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult) {
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		Set<String> authorizedScopes = authorizationRequest.getScopes();

		ArgumentCaptor<OAuth2AuthorizationConsent> authorizationConsentCaptor = ArgumentCaptor
			.forClass(OAuth2AuthorizationConsent.class);
		verify(this.authorizationConsentService).save(authorizationConsentCaptor.capture());
		OAuth2AuthorizationConsent authorizationConsent = authorizationConsentCaptor.getValue();

		assertThat(authorizationConsent.getRegisteredClientId()).isEqualTo(authorization.getRegisteredClientId());
		assertThat(authorizationConsent.getPrincipalName()).isEqualTo(authorization.getPrincipalName());
		assertThat(authorizationConsent.getAuthorities()).hasSize(authorizedScopes.size());
		assertThat(authorizationConsent.getScopes()).containsExactlyInAnyOrderElementsOf(authorizedScopes);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();

		assertThat(updatedAuthorization.getRegisteredClientId()).isEqualTo(authorization.getRegisteredClientId());
		assertThat(updatedAuthorization.getPrincipalName()).isEqualTo(authorization.getPrincipalName());
		assertThat(updatedAuthorization.getAuthorizationGrantType())
			.isEqualTo(authorization.getAuthorizationGrantType());
		assertThat(updatedAuthorization.<Authentication>getAttribute(Principal.class.getName()))
			.isEqualTo(authorization.<Authentication>getAttribute(Principal.class.getName()));
		assertThat(updatedAuthorization
			.<OAuth2AuthorizationRequest>getAttribute(OAuth2AuthorizationRequest.class.getName()))
			.isEqualTo(authorizationRequest);
		OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = updatedAuthorization
			.getToken(OAuth2AuthorizationCode.class);
		assertThat(authorizationCode).isNotNull();
		assertThat(updatedAuthorization.<String>getAttribute(OAuth2ParameterNames.STATE)).isNull();
		assertThat(updatedAuthorization.getAuthorizedScopes()).isEqualTo(authorizedScopes);

		assertThat(authenticationResult.getClientId()).isEqualTo(registeredClient.getClientId());
		assertThat(authenticationResult.getPrincipal()).isEqualTo(this.principal);
		assertThat(authenticationResult.getAuthorizationUri()).isEqualTo(authorizationRequest.getAuthorizationUri());
		assertThat(authenticationResult.getRedirectUri()).isEqualTo(authorizationRequest.getRedirectUri());
		assertThat(authenticationResult.getScopes()).isEqualTo(authorizedScopes);
		assertThat(authenticationResult.getState()).isEqualTo(authorizationRequest.getState());
		assertThat(authenticationResult.getAuthorizationCode()).isEqualTo(authorizationCode.getToken());
		assertThat(authenticationResult.isAuthenticated()).isTrue();
	}

	@Test
	public void authenticateWhenApproveNoneAndRevokePreviouslyApprovedThenAuthorizationConsentRemoved() {
		String previouslyApprovedScope = "message.read";
		String requestedScope = "message.write";
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scopes((scopes) -> {
			scopes.clear();
			scopes.add(previouslyApprovedScope);
			scopes.add(requestedScope);
		}).build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.principalName(this.principal.getName())
			.build();
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		OAuth2AuthorizationConsentAuthenticationToken authentication = new OAuth2AuthorizationConsentAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, STATE, new HashSet<>(), null); // No
																													// scopes
																													// approved
		given(this.authorizationService.findByToken(eq(authentication.getState()), eq(STATE_TOKEN_TYPE)))
			.willReturn(authorization);
		OAuth2AuthorizationConsent previousAuthorizationConsent = OAuth2AuthorizationConsent
			.withId(authorization.getRegisteredClientId(), authorization.getPrincipalName())
			.scope(previouslyApprovedScope)
			.build();
		given(this.authorizationConsentService.findById(eq(authorization.getRegisteredClientId()),
				eq(authorization.getPrincipalName())))
			.willReturn(previousAuthorizationConsent);

		// Revoke all (including previously approved)
		this.authenticationProvider.setAuthorizationConsentCustomizer(
				(authorizationConsentContext) -> authorizationConsentContext.getAuthorizationConsent()
					.authorities(Set::clear));

		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.satisfies((ex) -> assertAuthenticationException(ex, OAuth2ErrorCodes.ACCESS_DENIED,
					OAuth2ParameterNames.CLIENT_ID, authorizationRequest.getRedirectUri()));

		verify(this.authorizationConsentService).remove(eq(previousAuthorizationConsent));
		verify(this.authorizationService).remove(eq(authorization));
	}

	@Test
	public void authenticateWhenApproveSomeAndPreviouslyApprovedThenAuthorizationConsentUpdated() {
		String previouslyApprovedScope = "message.read";
		String requestedScope = "message.write";
		String otherPreviouslyApprovedScope = "other.scope";
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scopes((scopes) -> {
			scopes.clear();
			scopes.add(previouslyApprovedScope);
			scopes.add(requestedScope);
		}).build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.principalName(this.principal.getName())
			.build();
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		Set<String> requestedScopes = authorizationRequest.getScopes();
		OAuth2AuthorizationConsentAuthenticationToken authentication = new OAuth2AuthorizationConsentAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, STATE, requestedScopes, null);
		given(this.authorizationService.findByToken(eq(authentication.getState()), eq(STATE_TOKEN_TYPE)))
			.willReturn(authorization);
		OAuth2AuthorizationConsent previousAuthorizationConsent = OAuth2AuthorizationConsent
			.withId(authorization.getRegisteredClientId(), authorization.getPrincipalName())
			.scope(previouslyApprovedScope)
			.scope(otherPreviouslyApprovedScope)
			.build();
		given(this.authorizationConsentService.findById(eq(authorization.getRegisteredClientId()),
				eq(authorization.getPrincipalName())))
			.willReturn(previousAuthorizationConsent);

		OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult = (OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		ArgumentCaptor<OAuth2AuthorizationConsent> authorizationConsentCaptor = ArgumentCaptor
			.forClass(OAuth2AuthorizationConsent.class);
		verify(this.authorizationConsentService).save(authorizationConsentCaptor.capture());
		OAuth2AuthorizationConsent updatedAuthorizationConsent = authorizationConsentCaptor.getValue();

		assertThat(updatedAuthorizationConsent.getRegisteredClientId())
			.isEqualTo(previousAuthorizationConsent.getRegisteredClientId());
		assertThat(updatedAuthorizationConsent.getPrincipalName())
			.isEqualTo(previousAuthorizationConsent.getPrincipalName());
		assertThat(updatedAuthorizationConsent.getScopes()).containsExactlyInAnyOrder(previouslyApprovedScope,
				otherPreviouslyApprovedScope, requestedScope);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();
		assertThat(updatedAuthorization.getAuthorizedScopes()).isEqualTo(requestedScopes);
		assertThat(authenticationResult.getScopes()).isEqualTo(requestedScopes);
	}

	@Test
	public void authenticateWhenApproveNoneAndPreviouslyApprovedThenAuthorizationConsentNotUpdated() {
		String previouslyApprovedScope = "message.read";
		String requestedScope = "message.write";
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scopes((scopes) -> {
			scopes.clear();
			scopes.add(previouslyApprovedScope);
			scopes.add(requestedScope);
		}).build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.principalName(this.principal.getName())
			.build();
		OAuth2AuthorizationConsentAuthenticationToken authentication = new OAuth2AuthorizationConsentAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, STATE, new HashSet<>(), null); // No
																													// scopes
																													// approved
		given(this.authorizationService.findByToken(eq(authentication.getState()), eq(STATE_TOKEN_TYPE)))
			.willReturn(authorization);
		OAuth2AuthorizationConsent previousAuthorizationConsent = OAuth2AuthorizationConsent
			.withId(authorization.getRegisteredClientId(), authorization.getPrincipalName())
			.scope(previouslyApprovedScope)
			.build();
		given(this.authorizationConsentService.findById(eq(authorization.getRegisteredClientId()),
				eq(authorization.getPrincipalName())))
			.willReturn(previousAuthorizationConsent);

		OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult = (OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		verify(this.authorizationConsentService, never()).save(any());
		assertThat(authenticationResult.getScopes()).isEqualTo(Collections.singleton(previouslyApprovedScope));
	}

	private static void assertAuthenticationException(
			OAuth2AuthorizationCodeRequestAuthenticationException authenticationException, String errorCode,
			String parameterName, String redirectUri) {

		OAuth2Error error = authenticationException.getError();
		assertThat(error.getErrorCode()).isEqualTo(errorCode);
		assertThat(error.getDescription()).contains(parameterName);

		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = authenticationException
			.getAuthorizationCodeRequestAuthentication();
		assertThat(authorizationCodeRequestAuthentication.getRedirectUri()).isEqualTo(redirectUri);
	}

}
