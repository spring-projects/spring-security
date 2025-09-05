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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link OAuth2PushedAuthorizationRequestAuthenticationProvider}.
 *
 * @author Joe Grandja
 */
public class OAuth2PushedAuthorizationRequestAuthenticationProviderTests {

	private static final String AUTHORIZATION_URI = "https://provider.com/oauth2/par";

	private static final String STATE = "state";

	private OAuth2AuthorizationService authorizationService;

	private OAuth2PushedAuthorizationRequestAuthenticationProvider authenticationProvider;

	@BeforeEach
	public void setUp() {
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.authenticationProvider = new OAuth2PushedAuthorizationRequestAuthenticationProvider(
				this.authorizationService);
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2PushedAuthorizationRequestAuthenticationProvider(null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("authorizationService cannot be null");
	}

	@Test
	public void supportsWhenTypeOAuth2PushedAuthorizationRequestAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2PushedAuthorizationRequestAuthenticationToken.class))
			.isTrue();
	}

	@Test
	public void setAuthenticationValidatorWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authenticationProvider.setAuthenticationValidator(null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("authenticationValidator cannot be null");
	}

	@Test
	public void authenticateWhenClientNotAuthenticatedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		String redirectUri = registeredClient.getRedirectUris().toArray(new String[0])[1];
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
				registeredClient.getClientId(), ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null, null);
		OAuth2PushedAuthorizationRequestAuthenticationToken authentication = new OAuth2PushedAuthorizationRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), clientPrincipal, redirectUri, STATE,
				registeredClient.getScopes(), null);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
		// @formatter:on
	}

	@Test
	public void authenticateWhenClientNotAuthorizedToRequestCodeThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantTypes(Set::clear)
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.build();
		String redirectUri = registeredClient.getRedirectUris().toArray(new String[0])[1];
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2PushedAuthorizationRequestAuthenticationToken authentication = new OAuth2PushedAuthorizationRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), clientPrincipal, redirectUri, null,
				registeredClient.getScopes(), null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.satisfies((ex) -> assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
					OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, OAuth2ParameterNames.CLIENT_ID,
					authentication.getRedirectUri()));
	}

	@Test
	public void authenticateWhenInvalidRedirectUriHostThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2PushedAuthorizationRequestAuthenticationToken authentication = new OAuth2PushedAuthorizationRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), clientPrincipal, "https:///invalid", STATE,
				registeredClient.getScopes(), null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.satisfies((ex) -> assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
					OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI, null));
	}

	@Test
	public void authenticateWhenInvalidRedirectUriFragmentThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2PushedAuthorizationRequestAuthenticationToken authentication = new OAuth2PushedAuthorizationRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), clientPrincipal, "https://example.com#fragment",
				STATE, registeredClient.getScopes(), null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.satisfies((ex) -> assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
					OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI, null));
	}

	@Test
	public void authenticateWhenUnregisteredRedirectUriThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2PushedAuthorizationRequestAuthenticationToken authentication = new OAuth2PushedAuthorizationRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), clientPrincipal, "https://invalid-example.com",
				STATE, registeredClient.getScopes(), null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.satisfies((ex) -> assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
					OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI, null));
	}

	@Test
	public void authenticateWhenRedirectUriIPv4LoopbackAndDifferentPortThenReturnPushedAuthorizationResponse() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.redirectUri("https://127.0.0.1:8080")
			.build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2PushedAuthorizationRequestAuthenticationToken authentication = new OAuth2PushedAuthorizationRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), clientPrincipal, "https://127.0.0.1:5000", STATE,
				registeredClient.getScopes(), null);
		OAuth2PushedAuthorizationRequestAuthenticationToken authenticationResult = (OAuth2PushedAuthorizationRequestAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);
		assertPushedAuthorizationResponse(registeredClient, authentication, authenticationResult);
	}

	@Test
	public void authenticateWhenRedirectUriIPv6LoopbackAndDifferentPortThenReturnPushedAuthorizationResponse() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.redirectUri("https://[::1]:8080")
			.build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2PushedAuthorizationRequestAuthenticationToken authentication = new OAuth2PushedAuthorizationRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), clientPrincipal, "https://[::1]:5000", STATE,
				registeredClient.getScopes(), null);
		OAuth2PushedAuthorizationRequestAuthenticationToken authenticationResult = (OAuth2PushedAuthorizationRequestAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);
		assertPushedAuthorizationResponse(registeredClient, authentication, authenticationResult);
	}

	@Test
	public void authenticateWhenMissingRedirectUriAndMultipleRegisteredThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.redirectUri("https://example2.com")
			.build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2PushedAuthorizationRequestAuthenticationToken authentication = new OAuth2PushedAuthorizationRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), clientPrincipal, null, STATE,
				registeredClient.getScopes(), null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.satisfies((ex) -> assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
					OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI, null));
	}

	@Test
	public void authenticateWhenAuthenticationRequestMissingRedirectUriThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		// redirect_uri is REQUIRED for OpenID Connect requests
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scope(OidcScopes.OPENID).build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2PushedAuthorizationRequestAuthenticationToken authentication = new OAuth2PushedAuthorizationRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), clientPrincipal, null, STATE,
				registeredClient.getScopes(), null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.satisfies((ex) -> assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
					OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI, null));
	}

	@Test
	public void authenticateWhenInvalidScopeThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		String redirectUri = registeredClient.getRedirectUris().toArray(new String[0])[2];
		OAuth2PushedAuthorizationRequestAuthenticationToken authentication = new OAuth2PushedAuthorizationRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), clientPrincipal, redirectUri, STATE,
				Collections.singleton("invalid-scope"), null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.satisfies((ex) -> assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
					OAuth2ErrorCodes.INVALID_SCOPE, OAuth2ParameterNames.SCOPE, authentication.getRedirectUri()));
	}

	@Test
	public void authenticateWhenPkceRequiredAndMissingCodeChallengeThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.clientSettings(ClientSettings.builder().requireProofKey(true).build())
			.build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		String redirectUri = registeredClient.getRedirectUris().toArray(new String[0])[2];
		OAuth2PushedAuthorizationRequestAuthenticationToken authentication = new OAuth2PushedAuthorizationRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), clientPrincipal, redirectUri, STATE,
				registeredClient.getScopes(), null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.satisfies((ex) -> assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
					OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE,
					authentication.getRedirectUri()));
	}

	@Test
	public void authenticateWhenPkceUnsupportedCodeChallengeMethodThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		String redirectUri = registeredClient.getRedirectUris().toArray(new String[0])[2];
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE, "code-challenge");
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "unsupported");
		OAuth2PushedAuthorizationRequestAuthenticationToken authentication = new OAuth2PushedAuthorizationRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), clientPrincipal, redirectUri, STATE,
				registeredClient.getScopes(), additionalParameters);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.satisfies((ex) -> assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
					OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE_METHOD,
					authentication.getRedirectUri()));
	}

	@Test
	public void authenticateWhenPkceMissingCodeChallengeMethodThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		String redirectUri = registeredClient.getRedirectUris().toArray(new String[0])[2];
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE, "code-challenge");
		OAuth2PushedAuthorizationRequestAuthenticationToken authentication = new OAuth2PushedAuthorizationRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), clientPrincipal, redirectUri, STATE,
				registeredClient.getScopes(), additionalParameters);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.satisfies((ex) -> assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
					OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE_METHOD,
					authentication.getRedirectUri()));
	}

	@Test
	public void authenticateWhenAuthenticationRequestWithPromptNoneLoginThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		assertWhenAuthenticationRequestWithInvalidPromptThenThrowOAuth2AuthorizationCodeRequestAuthenticationException(
				"none login");
	}

	@Test
	public void authenticateWhenAuthenticationRequestWithPromptNoneConsentThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		assertWhenAuthenticationRequestWithInvalidPromptThenThrowOAuth2AuthorizationCodeRequestAuthenticationException(
				"none consent");
	}

	@Test
	public void authenticateWhenAuthenticationRequestWithPromptNoneSelectAccountThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		assertWhenAuthenticationRequestWithInvalidPromptThenThrowOAuth2AuthorizationCodeRequestAuthenticationException(
				"none select_account");
	}

	private void assertWhenAuthenticationRequestWithInvalidPromptThenThrowOAuth2AuthorizationCodeRequestAuthenticationException(
			String prompt) {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scope(OidcScopes.OPENID).build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		String redirectUri = registeredClient.getRedirectUris().toArray(new String[0])[2];
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put("prompt", prompt);
		OAuth2PushedAuthorizationRequestAuthenticationToken authentication = new OAuth2PushedAuthorizationRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), clientPrincipal, redirectUri, STATE,
				registeredClient.getScopes(), additionalParameters);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.satisfies((ex) -> assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
					OAuth2ErrorCodes.INVALID_REQUEST, "prompt", authentication.getRedirectUri()));
	}

	@Test
	public void authenticateWhenPushedAuthorizationRequestValidThenReturnPushedAuthorizationResponse() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		String redirectUri = registeredClient.getRedirectUris().toArray(new String[0])[0];
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE, "code-challenge");
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
		OAuth2PushedAuthorizationRequestAuthenticationToken authentication = new OAuth2PushedAuthorizationRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), clientPrincipal, redirectUri, STATE,
				registeredClient.getScopes(), additionalParameters);
		OAuth2PushedAuthorizationRequestAuthenticationToken authenticationResult = (OAuth2PushedAuthorizationRequestAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);
		assertPushedAuthorizationResponse(registeredClient, authentication, authenticationResult);
	}

	@Test
	public void authenticateWhenCustomAuthenticationValidatorThenUsed() {
		@SuppressWarnings("unchecked")
		Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator = mock(Consumer.class);
		this.authenticationProvider.setAuthenticationValidator(authenticationValidator);

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		String redirectUri = registeredClient.getRedirectUris().toArray(new String[0])[2];
		OAuth2PushedAuthorizationRequestAuthenticationToken authentication = new OAuth2PushedAuthorizationRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), clientPrincipal, redirectUri, STATE,
				registeredClient.getScopes(), null);
		OAuth2PushedAuthorizationRequestAuthenticationToken authenticationResult = (OAuth2PushedAuthorizationRequestAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);
		assertPushedAuthorizationResponse(registeredClient, authentication, authenticationResult);
		verify(authenticationValidator).accept(any());
	}

	private void assertPushedAuthorizationResponse(RegisteredClient registeredClient,
			OAuth2PushedAuthorizationRequestAuthenticationToken authentication,
			OAuth2PushedAuthorizationRequestAuthenticationToken authenticationResult) {

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization authorization = authorizationCaptor.getValue();

		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		assertThat(authorizationRequest.getGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(authorizationRequest.getResponseType()).isEqualTo(OAuth2AuthorizationResponseType.CODE);
		assertThat(authorizationRequest.getAuthorizationUri()).isEqualTo(authentication.getAuthorizationUri());
		assertThat(authorizationRequest.getClientId()).isEqualTo(registeredClient.getClientId());
		assertThat(authorizationRequest.getRedirectUri()).isEqualTo(authentication.getRedirectUri());
		assertThat(authorizationRequest.getScopes()).isEqualTo(authentication.getScopes());
		assertThat(authorizationRequest.getState()).isEqualTo(authentication.getState());
		assertThat(authorizationRequest.getAdditionalParameters()).isEqualTo(authentication.getAdditionalParameters());

		assertThat(authorization.getRegisteredClientId()).isEqualTo(registeredClient.getId());
		assertThat(authorization.getPrincipalName()).isEqualTo(authentication.getName());
		assertThat(authorization.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(authorization.<String>getAttribute(OAuth2ParameterNames.STATE)).isNotNull();

		assertThat(authenticationResult.getClientId()).isEqualTo(authorizationRequest.getClientId());
		assertThat(authenticationResult.getPrincipal()).isEqualTo(authentication.getPrincipal());
		assertThat(authenticationResult.getAuthorizationUri()).isEqualTo(authorizationRequest.getAuthorizationUri());
		assertThat(authenticationResult.getRedirectUri()).isEqualTo(authorizationRequest.getRedirectUri());
		assertThat(authenticationResult.getScopes()).isEqualTo(authorizationRequest.getScopes());
		assertThat(authenticationResult.getState()).isEqualTo(authorizationRequest.getState());
		assertThat(authenticationResult.getRequestUri()).isNotNull();
		assertThat(authenticationResult.getRequestUriExpiresAt()).isNotNull();
		assertThat(authenticationResult.isAuthenticated()).isTrue();
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
