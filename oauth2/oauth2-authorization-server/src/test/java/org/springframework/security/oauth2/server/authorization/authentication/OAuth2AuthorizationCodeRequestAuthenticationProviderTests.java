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
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Predicate;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
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
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link OAuth2AuthorizationCodeRequestAuthenticationProvider}.
 *
 * @author Joe Grandja
 * @author Steve Riesenberg
 */
public class OAuth2AuthorizationCodeRequestAuthenticationProviderTests {

	private static final String AUTHORIZATION_URI = "https://provider.com/oauth2/authorize";

	// See RFC 7636: Appendix B. Example for the S256 code_challenge_method
	// https://tools.ietf.org/html/rfc7636#appendix-B
	private static final String S256_CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

	private static final String S256_CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

	private static final String STATE = "state";

	private static final OAuth2TokenType STATE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.STATE);

	private RegisteredClientRepository registeredClientRepository;

	private OAuth2AuthorizationService authorizationService;

	private OAuth2AuthorizationConsentService authorizationConsentService;

	private OAuth2AuthorizationCodeRequestAuthenticationProvider authenticationProvider;

	private TestingAuthenticationToken principal;

	@BeforeEach
	public void setUp() {
		this.registeredClientRepository = mock(RegisteredClientRepository.class);
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.authorizationConsentService = mock(OAuth2AuthorizationConsentService.class);
		this.authenticationProvider = new OAuth2AuthorizationCodeRequestAuthenticationProvider(
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
			.isThrownBy(() -> new OAuth2AuthorizationCodeRequestAuthenticationProvider(null, this.authorizationService,
					this.authorizationConsentService))
			.withMessage("registeredClientRepository cannot be null");
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> new OAuth2AuthorizationCodeRequestAuthenticationProvider(this.registeredClientRepository,
					null, this.authorizationConsentService))
			.isInstanceOf(IllegalArgumentException.class)
			.withMessage("authorizationService cannot be null");
	}

	@Test
	public void constructorWhenAuthorizationConsentServiceNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> new OAuth2AuthorizationCodeRequestAuthenticationProvider(this.registeredClientRepository,
					this.authorizationService, null))
			.withMessage("authorizationConsentService cannot be null");
	}

	@Test
	public void supportsWhenTypeOAuth2AuthorizationCodeRequestAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2AuthorizationCodeRequestAuthenticationToken.class))
			.isTrue();
	}

	@Test
	public void setAuthorizationCodeGeneratorWhenNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.authenticationProvider.setAuthorizationCodeGenerator(null))
			.withMessage("authorizationCodeGenerator cannot be null");
	}

	@Test
	public void setAuthenticationValidatorWhenNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.authenticationProvider.setAuthenticationValidator(null))
			.isInstanceOf(IllegalArgumentException.class)
			.withMessage("authenticationValidator cannot be null");
	}

	@Test
	public void setAuthorizationConsentRequiredWhenNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.authenticationProvider.setAuthorizationConsentRequired(null))
			.withMessage("authorizationConsentRequired cannot be null");
	}

	@Test
	public void authenticateWhenInvalidClientIdThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		String redirectUri = registeredClient.getRedirectUris().toArray(new String[0])[1];
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, redirectUri, STATE,
				registeredClient.getScopes(), null);
		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.satisfies((ex) -> assertAuthenticationException(ex, OAuth2ErrorCodes.INVALID_REQUEST,
					OAuth2ParameterNames.CLIENT_ID, null));
	}

	// gh-243
	@Test
	public void authenticateWhenInvalidRedirectUriHostThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, "https:///invalid", STATE,
				registeredClient.getScopes(), null);
		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.satisfies((ex) -> assertAuthenticationException(ex, OAuth2ErrorCodes.INVALID_REQUEST,
					OAuth2ParameterNames.REDIRECT_URI, null));
	}

	// gh-243
	@Test
	public void authenticateWhenInvalidRedirectUriFragmentThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, "https://example.com#fragment",
				STATE, registeredClient.getScopes(), null);
		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.satisfies((ex) -> assertAuthenticationException(ex, OAuth2ErrorCodes.INVALID_REQUEST,
					OAuth2ParameterNames.REDIRECT_URI, null));
	}

	@Test
	public void authenticateWhenUnregisteredRedirectUriThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, "https://invalid-example.com", STATE,
				registeredClient.getScopes(), null);
		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.satisfies((ex) -> assertAuthenticationException(ex, OAuth2ErrorCodes.INVALID_REQUEST,
					OAuth2ParameterNames.REDIRECT_URI, null));
	}

	// gh-243
	@Test
	public void authenticateWhenRedirectUriIPv4LoopbackAndDifferentPortThenReturnAuthorizationCode() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.redirectUri("https://127.0.0.1:8080")
			.build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, "https://127.0.0.1:5000", STATE,
				registeredClient.getScopes(), createPkceParameters());

		OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult = (OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		assertAuthorizationCodeRequestWithAuthorizationCodeResult(registeredClient, authentication,
				authenticationResult);
	}

	// gh-243
	@Test
	public void authenticateWhenRedirectUriIPv6LoopbackAndDifferentPortThenReturnAuthorizationCode() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.redirectUri("https://[::1]:8080")
			.build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, "https://[::1]:5000", STATE,
				registeredClient.getScopes(), createPkceParameters());

		OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult = (OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		assertAuthorizationCodeRequestWithAuthorizationCodeResult(registeredClient, authentication,
				authenticationResult);
	}

	@Test
	public void authenticateWhenMissingRedirectUriAndMultipleRegisteredThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.redirectUri("https://example2.com")
			.build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, null, STATE,
				registeredClient.getScopes(), null);
		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.satisfies((ex) -> assertAuthenticationException(ex, OAuth2ErrorCodes.INVALID_REQUEST,
					OAuth2ParameterNames.REDIRECT_URI, null));
	}

	@Test
	public void authenticateWhenAuthenticationRequestMissingRedirectUriThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		// redirect_uri is REQUIRED for OpenID Connect requests
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scope(OidcScopes.OPENID).build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, null, STATE,
				registeredClient.getScopes(), null);
		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.satisfies((ex) -> assertAuthenticationException(ex, OAuth2ErrorCodes.INVALID_REQUEST,
					OAuth2ParameterNames.REDIRECT_URI, null));
	}

	@Test
	public void authenticateWhenClientNotAuthorizedToRequestCodeThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantTypes(Set::clear)
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);
		String redirectUri = registeredClient.getRedirectUris().toArray(new String[0])[1];
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, redirectUri, STATE,
				registeredClient.getScopes(), null);
		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.satisfies((ex) -> assertAuthenticationException(ex, OAuth2ErrorCodes.UNAUTHORIZED_CLIENT,
					OAuth2ParameterNames.CLIENT_ID, authentication.getRedirectUri()));
	}

	@Test
	public void authenticateWhenInvalidScopeThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);
		String redirectUri = registeredClient.getRedirectUris().toArray(new String[0])[2];
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, redirectUri, STATE,
				Collections.singleton("invalid-scope"), null);
		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.satisfies((ex) -> assertAuthenticationException(ex, OAuth2ErrorCodes.INVALID_SCOPE,
					OAuth2ParameterNames.SCOPE, authentication.getRedirectUri()));
	}

	@Test
	public void authenticateWhenPkceRequiredAndMissingCodeChallengeThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);
		String redirectUri = registeredClient.getRedirectUris().toArray(new String[0])[2];
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, redirectUri, STATE,
				registeredClient.getScopes(), null);
		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.satisfies((ex) -> assertAuthenticationException(ex, OAuth2ErrorCodes.INVALID_REQUEST,
					PkceParameterNames.CODE_CHALLENGE, authentication.getRedirectUri()));
	}

	@Test
	public void authenticateWhenPkceUnsupportedCodeChallengeMethodThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);
		String redirectUri = registeredClient.getRedirectUris().toArray(new String[0])[0];
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE, S256_CODE_CHALLENGE);
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "unsupported");
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, redirectUri, STATE,
				registeredClient.getScopes(), additionalParameters);
		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.satisfies((ex) -> assertAuthenticationException(ex, OAuth2ErrorCodes.INVALID_REQUEST,
					PkceParameterNames.CODE_CHALLENGE_METHOD, authentication.getRedirectUri()));
	}

	// gh-770
	@Test
	public void authenticateWhenPkceMissingCodeChallengeMethodThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);
		String redirectUri = registeredClient.getRedirectUris().toArray(new String[0])[2];
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE, S256_CODE_CHALLENGE);
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, redirectUri, STATE,
				registeredClient.getScopes(), additionalParameters);
		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.satisfies((ex) -> assertAuthenticationException(ex, OAuth2ErrorCodes.INVALID_REQUEST,
					PkceParameterNames.CODE_CHALLENGE_METHOD, authentication.getRedirectUri()));
	}

	@Test
	public void authenticateWhenAuthenticationRequestWithPromptNoneLoginThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		assertWhenAuthenticationRequestWithPromptThenThrowOAuth2AuthorizationCodeRequestAuthenticationException(
				"none login");
	}

	@Test
	public void authenticateWhenAuthenticationRequestWithPromptNoneConsentThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		assertWhenAuthenticationRequestWithPromptThenThrowOAuth2AuthorizationCodeRequestAuthenticationException(
				"none consent");
	}

	@Test
	public void authenticateWhenAuthenticationRequestWithPromptNoneSelectAccountThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		assertWhenAuthenticationRequestWithPromptThenThrowOAuth2AuthorizationCodeRequestAuthenticationException(
				"none select_account");
	}

	private void assertWhenAuthenticationRequestWithPromptThenThrowOAuth2AuthorizationCodeRequestAuthenticationException(
			String prompt) {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scope(OidcScopes.OPENID).build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);
		String redirectUri = registeredClient.getRedirectUris().toArray(new String[0])[2];
		Map<String, Object> additionalParameters = createPkceParameters();
		additionalParameters.put("prompt", prompt);
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, redirectUri, STATE,
				registeredClient.getScopes(), additionalParameters);
		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.satisfies((ex) -> assertAuthenticationException(ex, OAuth2ErrorCodes.INVALID_REQUEST, "prompt",
					authentication.getRedirectUri()));
	}

	@Test
	public void authenticateWhenPrincipalNotAuthenticatedAndPromptNoneThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scope(OidcScopes.OPENID).build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);
		this.principal.setAuthenticated(false);
		String redirectUri = registeredClient.getRedirectUris().toArray(new String[0])[2];
		Map<String, Object> additionalParameters = createPkceParameters();
		additionalParameters.put("prompt", "none");
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, redirectUri, STATE,
				registeredClient.getScopes(), additionalParameters);
		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.satisfies((ex) -> assertAuthenticationException(ex, "login_required", "prompt",
					authentication.getRedirectUri()));
	}

	@Test
	public void authenticateWhenPrincipalNotAuthenticatedThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);
		this.principal.setAuthenticated(false);

		String redirectUri = registeredClient.getRedirectUris().toArray(new String[0])[1];
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, redirectUri, STATE,
				registeredClient.getScopes(), createPkceParameters());
		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.satisfies((ex) -> assertAuthenticationException(ex, OAuth2ErrorCodes.INVALID_REQUEST, "principal",
					authentication.getRedirectUri()));
	}

	@Test
	public void authenticateWhenRequireAuthorizationConsentAndPromptNoneThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.scope(OidcScopes.OPENID)
			.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
			.build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);
		String redirectUri = registeredClient.getRedirectUris().toArray(new String[0])[2];
		Map<String, Object> additionalParameters = createPkceParameters();
		additionalParameters.put("prompt", "none");
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, redirectUri, STATE,
				registeredClient.getScopes(), additionalParameters);
		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.satisfies((ex) -> assertAuthenticationException(ex, "consent_required", "prompt",
					authentication.getRedirectUri()));
	}

	@Test
	public void authenticateWhenRequireAuthorizationConsentThenReturnAuthorizationConsent() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
			.build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);

		String redirectUri = registeredClient.getRedirectUris().toArray(new String[0])[0];
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, redirectUri, STATE,
				registeredClient.getScopes(), createPkceParameters());

		OAuth2AuthorizationConsentAuthenticationToken authenticationResult = (OAuth2AuthorizationConsentAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

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
		assertThat(authorization.getPrincipalName()).isEqualTo(this.principal.getName());
		assertThat(authorization.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(authorization.<Authentication>getAttribute(Principal.class.getName())).isEqualTo(this.principal);
		String state = authorization.getAttribute(OAuth2ParameterNames.STATE);
		assertThat(state).isNotNull();
		assertThat(state).isNotEqualTo(authentication.getState());

		assertThat(authenticationResult.getClientId()).isEqualTo(registeredClient.getClientId());
		assertThat(authenticationResult.getPrincipal()).isEqualTo(this.principal);
		assertThat(authenticationResult.getAuthorizationUri()).isEqualTo(authorizationRequest.getAuthorizationUri());
		assertThat(authenticationResult.getScopes()).isEmpty();
		assertThat(authenticationResult.getState()).isEqualTo(state);
		assertThat(authenticationResult.isAuthenticated()).isTrue();
	}

	@Test
	public void authenticateWhenRequireAuthorizationConsentAndOnlyOpenidScopeRequestedThenAuthorizationConsentNotRequired() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
			.scopes((scopes) -> {
				scopes.clear();
				scopes.add(OidcScopes.OPENID);
			})
			.build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);

		String redirectUri = registeredClient.getRedirectUris().toArray(new String[0])[1];
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, redirectUri, STATE,
				registeredClient.getScopes(), createPkceParameters());

		OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult = (OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		assertAuthorizationCodeRequestWithAuthorizationCodeResult(registeredClient, authentication,
				authenticationResult);
	}

	@Test
	public void authenticateWhenRequireAuthorizationConsentAndAllPreviouslyApprovedThenAuthorizationConsentNotRequired() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
			.build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);

		OAuth2AuthorizationConsent.Builder builder = OAuth2AuthorizationConsent.withId(registeredClient.getId(),
				this.principal.getName());
		registeredClient.getScopes().forEach(builder::scope);
		OAuth2AuthorizationConsent previousAuthorizationConsent = builder.build();
		given(this.authorizationConsentService.findById(eq(registeredClient.getId()), eq(this.principal.getName())))
			.willReturn(previousAuthorizationConsent);

		String redirectUri = registeredClient.getRedirectUris().toArray(new String[0])[2];
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, redirectUri, STATE,
				registeredClient.getScopes(), createPkceParameters());

		OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult = (OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		assertAuthorizationCodeRequestWithAuthorizationCodeResult(registeredClient, authentication,
				authenticationResult);
	}

	@Test
	public void authenticateWhenCustomAuthorizationConsentRequiredThenUsed() {
		@SuppressWarnings("unchecked")
		Predicate<OAuth2AuthorizationCodeRequestAuthenticationContext> authorizationConsentRequired = mock(
				Predicate.class);
		this.authenticationProvider.setAuthorizationConsentRequired(authorizationConsentRequired);

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);

		String redirectUri = registeredClient.getRedirectUris().toArray(new String[0])[1];
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, redirectUri, STATE,
				registeredClient.getScopes(), createPkceParameters());

		OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult = (OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		assertAuthorizationCodeRequestWithAuthorizationCodeResult(registeredClient, authentication,
				authenticationResult);

		verify(authorizationConsentRequired).test(any());
	}

	@Test
	public void authenticateWhenAuthorizationCodeRequestValidThenReturnAuthorizationCode() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);

		String redirectUri = registeredClient.getRedirectUris().toArray(new String[0])[0];
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, redirectUri, STATE,
				registeredClient.getScopes(), createPkceParameters());

		OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult = (OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		assertAuthorizationCodeRequestWithAuthorizationCodeResult(registeredClient, authentication,
				authenticationResult);
	}

	@Test
	public void authenticateWhenAuthorizationCodeRequestWithRequestUriThenReturnAuthorizationCode() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);

		OAuth2PushedAuthorizationRequestUri pushedAuthorizationRequestUri = OAuth2PushedAuthorizationRequestUri
			.create();
		Map<String, Object> additionalParameters = createPkceParameters();
		additionalParameters.put(OAuth2ParameterNames.REQUEST_URI, pushedAuthorizationRequestUri.getRequestUri());
		OAuth2Authorization authorization = TestOAuth2Authorizations
			.authorization(registeredClient, additionalParameters)
			.build();
		given(this.authorizationService.findByToken(eq(pushedAuthorizationRequestUri.getState()), eq(STATE_TOKEN_TYPE)))
			.willReturn(authorization);

		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, null, null, null,
				additionalParameters);

		OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult = (OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		assertAuthorizationCodeRequestWithAuthorizationCodeResult(registeredClient, authentication,
				authenticationResult);
		verify(this.authorizationService).remove(eq(authorization));
	}

	@Test
	public void authenticateWhenAuthorizationCodeRequestWithInvalidRequestUriThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();

		OAuth2PushedAuthorizationRequestUri pushedAuthorizationRequestUri = OAuth2PushedAuthorizationRequestUri
			.create();
		Map<String, Object> additionalParameters = createPkceParameters();
		additionalParameters.put(OAuth2ParameterNames.REQUEST_URI, pushedAuthorizationRequestUri.getRequestUri());
		OAuth2Authorization authorization = TestOAuth2Authorizations
			.authorization(registeredClient, additionalParameters)
			.build();
		given(this.authorizationService.findByToken(eq(pushedAuthorizationRequestUri.getState()), eq(STATE_TOKEN_TYPE)))
			.willReturn(authorization);

		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, null, null, null,
				Collections.singletonMap(OAuth2ParameterNames.REQUEST_URI, "invalid_request_uri"));

		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.satisfies((ex) -> assertAuthenticationException(ex, OAuth2ErrorCodes.INVALID_REQUEST,
					OAuth2ParameterNames.REQUEST_URI, null));
	}

	@Test
	public void authenticateWhenAuthorizationCodeRequestWithRequestUriIssuedToAnotherClientThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		RegisteredClient anotherRegisteredClient = TestRegisteredClients.registeredClient2().build();

		OAuth2PushedAuthorizationRequestUri pushedAuthorizationRequestUri = OAuth2PushedAuthorizationRequestUri
			.create();
		Map<String, Object> additionalParameters = createPkceParameters();
		additionalParameters.put(OAuth2ParameterNames.REQUEST_URI, pushedAuthorizationRequestUri.getRequestUri());
		OAuth2Authorization authorization = TestOAuth2Authorizations
			.authorization(registeredClient, additionalParameters)
			.build();
		given(this.authorizationService.findByToken(eq(pushedAuthorizationRequestUri.getState()), eq(STATE_TOKEN_TYPE)))
			.willReturn(authorization);

		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, anotherRegisteredClient.getClientId(), this.principal, null, null, null,
				additionalParameters);

		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.satisfies((ex) -> assertAuthenticationException(ex, OAuth2ErrorCodes.INVALID_REQUEST,
					OAuth2ParameterNames.CLIENT_ID, null));
	}

	@Test
	public void authenticateWhenAuthorizationCodeRequestWithExpiredRequestUriThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();

		OAuth2PushedAuthorizationRequestUri pushedAuthorizationRequestUri = OAuth2PushedAuthorizationRequestUri
			.create(Instant.now().minusSeconds(5));
		Map<String, Object> additionalParameters = createPkceParameters();
		additionalParameters.put(OAuth2ParameterNames.REQUEST_URI, pushedAuthorizationRequestUri.getRequestUri());
		OAuth2Authorization authorization = TestOAuth2Authorizations
			.authorization(registeredClient, additionalParameters)
			.build();
		given(this.authorizationService.findByToken(eq(pushedAuthorizationRequestUri.getState()), eq(STATE_TOKEN_TYPE)))
			.willReturn(authorization);

		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, null, null, null,
				additionalParameters);

		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.satisfies((ex) -> assertAuthenticationException(ex, OAuth2ErrorCodes.INVALID_REQUEST,
					OAuth2ParameterNames.REQUEST_URI, null));
		verify(this.authorizationService).remove(eq(authorization));
	}

	@Test
	public void authenticateWhenAuthorizationCodeNotGeneratedThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);

		@SuppressWarnings("unchecked")
		OAuth2TokenGenerator<OAuth2AuthorizationCode> authorizationCodeGenerator = mock(OAuth2TokenGenerator.class);
		this.authenticationProvider.setAuthorizationCodeGenerator(authorizationCodeGenerator);

		String redirectUri = registeredClient.getRedirectUris().toArray(new String[0])[1];
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, redirectUri, STATE,
				registeredClient.getScopes(), createPkceParameters());

		assertThatExceptionOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.extracting(OAuth2AuthenticationException::getError)
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.SERVER_ERROR);
				assertThat(error.getDescription())
					.contains("The token generator failed to generate the authorization code.");
			});
	}

	@Test
	public void authenticateWhenCustomAuthenticationValidatorThenUsed() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);

		@SuppressWarnings("unchecked")
		Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator = mock(Consumer.class);
		this.authenticationProvider.setAuthenticationValidator(authenticationValidator);

		String redirectUri = registeredClient.getRedirectUris().toArray(new String[0])[2];
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, redirectUri, STATE,
				registeredClient.getScopes(), createPkceParameters());

		OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult = (OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		assertAuthorizationCodeRequestWithAuthorizationCodeResult(registeredClient, authentication,
				authenticationResult);

		verify(authenticationValidator).accept(any());
	}

	private void assertAuthorizationCodeRequestWithAuthorizationCodeResult(RegisteredClient registeredClient,
			OAuth2AuthorizationCodeRequestAuthenticationToken authentication,
			OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult) {

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization authorization = authorizationCaptor.getValue();

		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		assertThat(authorizationRequest.getGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(authorizationRequest.getResponseType()).isEqualTo(OAuth2AuthorizationResponseType.CODE);
		assertThat(authorizationRequest.getAuthorizationUri()).isEqualTo(authentication.getAuthorizationUri());
		assertThat(authorizationRequest.getClientId()).isEqualTo(registeredClient.getClientId());

		String requestUri = (String) authentication.getAdditionalParameters().get(OAuth2ParameterNames.REQUEST_URI);
		if (!StringUtils.hasText(requestUri)) {
			assertThat(authorizationRequest.getRedirectUri()).isEqualTo(authentication.getRedirectUri());
			assertThat(authorizationRequest.getScopes()).isEqualTo(authentication.getScopes());
			assertThat(authorizationRequest.getState()).isEqualTo(authentication.getState());
		}

		assertThat(authorizationRequest.getAdditionalParameters()).isEqualTo(authentication.getAdditionalParameters());
		assertThat(authorization.getRegisteredClientId()).isEqualTo(registeredClient.getId());
		assertThat(authorization.getPrincipalName()).isEqualTo(this.principal.getName());
		assertThat(authorization.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(authorization.<Authentication>getAttribute(Principal.class.getName())).isEqualTo(this.principal);

		OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = authorization
			.getToken(OAuth2AuthorizationCode.class);
		Set<String> authorizedScopes = authorization.getAuthorizedScopes();

		assertThat(authenticationResult.getClientId()).isEqualTo(registeredClient.getClientId());
		assertThat(authenticationResult.getPrincipal()).isEqualTo(this.principal);
		assertThat(authenticationResult.getAuthorizationUri()).isEqualTo(authorizationRequest.getAuthorizationUri());
		assertThat(authenticationResult.getRedirectUri()).isEqualTo(authorizationRequest.getRedirectUri());
		assertThat(authenticationResult.getScopes()).isEqualTo(authorizedScopes);
		assertThat(authenticationResult.getState()).isEqualTo(authorizationRequest.getState());
		assertThat(authenticationResult.getAuthorizationCode()).isEqualTo(authorizationCode.getToken());
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

	private static Map<String, Object> createPkceParameters() {
		Map<String, Object> parameters = new HashMap<>();
		parameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
		parameters.put(PkceParameterNames.CODE_CHALLENGE, S256_CODE_CHALLENGE);
		return parameters;
	}

}
