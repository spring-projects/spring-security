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

package org.springframework.security.oauth2.server.authorization.web;

import java.nio.charset.StandardCharsets;
import java.text.MessageFormat;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.context.TestAuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link OAuth2AuthorizationEndpointFilter}.
 *
 * @author Paurav Munshi
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 * @author Anoop Garlapati
 * @author Dmitriy Dubson
 * @author Greg Li
 * @since 0.0.1
 */
public class OAuth2AuthorizationEndpointFilterTests {

	private static final String DEFAULT_AUTHORIZATION_ENDPOINT_URI = "/oauth2/authorize";

	private static final String AUTHORIZATION_URI = "https://provider.com/oauth2/authorize";

	private static final String STATE = "state";

	private static final String REMOTE_ADDRESS = "remote-address";

	private AuthenticationManager authenticationManager;

	private OAuth2AuthorizationEndpointFilter filter;

	private TestingAuthenticationToken principal;

	private OAuth2AuthorizationCode authorizationCode;

	@BeforeEach
	public void setUp() {
		this.authenticationManager = mock(AuthenticationManager.class);
		this.filter = new OAuth2AuthorizationEndpointFilter(this.authenticationManager);
		this.principal = new TestingAuthenticationToken("principalName", "password");
		this.principal.setAuthenticated(true);
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(this.principal);
		SecurityContextHolder.setContext(securityContext);
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(5, ChronoUnit.MINUTES);
		this.authorizationCode = new OAuth2AuthorizationCode("code", issuedAt, expiresAt);
		AuthorizationServerContextHolder
			.setContext(new TestAuthorizationServerContext(AuthorizationServerSettings.builder().build(), null));
	}

	@AfterEach
	public void cleanup() {
		SecurityContextHolder.clearContext();
		AuthorizationServerContextHolder.resetContext();
	}

	@Test
	public void constructorWhenAuthenticationManagerNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> new OAuth2AuthorizationEndpointFilter(null))
			.withMessage("authenticationManager cannot be null");
	}

	@Test
	public void constructorWhenAuthorizationEndpointUriNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> new OAuth2AuthorizationEndpointFilter(this.authenticationManager, null))
			.withMessage("authorizationEndpointUri cannot be empty");
	}

	@Test
	public void setAuthenticationDetailsSourceWhenNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.filter.setAuthenticationDetailsSource(null))
			.withMessage("authenticationDetailsSource cannot be null");
	}

	@Test
	public void setAuthenticationConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.filter.setAuthenticationConverter(null))
			.withMessage("authenticationConverter cannot be null");
	}

	@Test
	public void setAuthenticationSuccessHandlerWhenNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.filter.setAuthenticationSuccessHandler(null))
			.withMessage("authenticationSuccessHandler cannot be null");
	}

	@Test
	public void setAuthenticationFailureHandlerWhenNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.filter.setAuthenticationFailureHandler(null))
			.withMessage("authenticationFailureHandler cannot be null");
	}

	@Test
	public void setSessionAuthenticationStrategyWhenNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.filter.setSessionAuthenticationStrategy(null))
			.withMessage("sessionAuthenticationStrategy cannot be null");
	}

	@Test
	public void doFilterWhenNotAuthorizationRequestThenNotProcessed() throws Exception {
		String requestUri = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenAuthorizationRequestMultipleRequestUriThenInvalidRequestError() throws Exception {
		doFilterWhenAuthorizationRequestInvalidParameterThenError(TestRegisteredClients.registeredClient().build(),
				OAuth2ParameterNames.REQUEST_URI, OAuth2ErrorCodes.INVALID_REQUEST, (request) -> {
					request.addParameter(OAuth2ParameterNames.REQUEST_URI, OAuth2ParameterNames.REQUEST_URI);
					request.addParameter(OAuth2ParameterNames.REQUEST_URI, "request_uri_2");
					updateQueryString(request);
				});
	}

	@Test
	public void doFilterWhenAuthorizationRequestMissingResponseTypeThenInvalidRequestError() throws Exception {
		doFilterWhenAuthorizationRequestInvalidParameterThenError(TestRegisteredClients.registeredClient().build(),
				OAuth2ParameterNames.RESPONSE_TYPE, OAuth2ErrorCodes.INVALID_REQUEST, (request) -> {
					request.removeParameter(OAuth2ParameterNames.RESPONSE_TYPE);
					updateQueryString(request);
				});
	}

	@Test
	public void doFilterWhenAuthorizationRequestMultipleResponseTypeThenInvalidRequestError() throws Exception {
		doFilterWhenAuthorizationRequestInvalidParameterThenError(TestRegisteredClients.registeredClient().build(),
				OAuth2ParameterNames.RESPONSE_TYPE, OAuth2ErrorCodes.INVALID_REQUEST, (request) -> {
					request.addParameter(OAuth2ParameterNames.RESPONSE_TYPE, "id_token");
					updateQueryString(request);
				});
	}

	@Test
	public void doFilterWhenAuthorizationRequestInvalidResponseTypeThenUnsupportedResponseTypeError() throws Exception {
		doFilterWhenAuthorizationRequestInvalidParameterThenError(TestRegisteredClients.registeredClient().build(),
				OAuth2ParameterNames.RESPONSE_TYPE, OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE, (request) -> {
					request.setParameter(OAuth2ParameterNames.RESPONSE_TYPE, "id_token");
					updateQueryString(request);
				});
	}

	@Test
	public void doFilterWhenAuthorizationRequestMissingClientIdThenInvalidRequestError() throws Exception {
		doFilterWhenAuthorizationRequestInvalidParameterThenError(TestRegisteredClients.registeredClient().build(),
				OAuth2ParameterNames.CLIENT_ID, OAuth2ErrorCodes.INVALID_REQUEST, (request) -> {
					request.removeParameter(OAuth2ParameterNames.CLIENT_ID);
					updateQueryString(request);
				});
	}

	@Test
	public void doFilterWhenAuthorizationRequestMultipleClientIdThenInvalidRequestError() throws Exception {
		doFilterWhenAuthorizationRequestInvalidParameterThenError(TestRegisteredClients.registeredClient().build(),
				OAuth2ParameterNames.CLIENT_ID, OAuth2ErrorCodes.INVALID_REQUEST, (request) -> {
					request.addParameter(OAuth2ParameterNames.CLIENT_ID, "client-2");
					updateQueryString(request);
				});
	}

	@Test
	public void doFilterWhenAuthorizationRequestMultipleRedirectUriThenInvalidRequestError() throws Exception {
		doFilterWhenAuthorizationRequestInvalidParameterThenError(TestRegisteredClients.registeredClient().build(),
				OAuth2ParameterNames.REDIRECT_URI, OAuth2ErrorCodes.INVALID_REQUEST, (request) -> {
					request.addParameter(OAuth2ParameterNames.REDIRECT_URI, "https://example2.com");
					updateQueryString(request);
				});
	}

	@Test
	public void doFilterWhenAuthorizationRequestMultipleScopeThenInvalidRequestError() throws Exception {
		doFilterWhenAuthorizationRequestInvalidParameterThenError(TestRegisteredClients.registeredClient().build(),
				OAuth2ParameterNames.SCOPE, OAuth2ErrorCodes.INVALID_REQUEST, (request) -> {
					request.addParameter(OAuth2ParameterNames.SCOPE, "scope2");
					updateQueryString(request);
				});
	}

	@Test
	public void doFilterWhenAuthorizationRequestMultipleStateThenInvalidRequestError() throws Exception {
		doFilterWhenAuthorizationRequestInvalidParameterThenError(TestRegisteredClients.registeredClient().build(),
				OAuth2ParameterNames.STATE, OAuth2ErrorCodes.INVALID_REQUEST, (request) -> {
					request.addParameter(OAuth2ParameterNames.STATE, "state2");
					updateQueryString(request);
				});
	}

	@Test
	public void doFilterWhenAuthorizationConsentRequestMissingStateThenInvalidRequestError() throws Exception {
		doFilterWhenAuthorizationConsentRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(), OAuth2ParameterNames.STATE,
				OAuth2ErrorCodes.INVALID_REQUEST, (request) -> request.removeParameter(OAuth2ParameterNames.STATE));
	}

	@Test
	public void doFilterWhenAuthorizationConsentRequestMultipleStateThenInvalidRequestError() throws Exception {
		doFilterWhenAuthorizationConsentRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(), OAuth2ParameterNames.STATE,
				OAuth2ErrorCodes.INVALID_REQUEST,
				(request) -> request.addParameter(OAuth2ParameterNames.STATE, "state2"));
	}

	@Test
	public void doFilterWhenAuthorizationRequestMultipleCodeChallengeThenInvalidRequestError() throws Exception {
		doFilterWhenAuthorizationRequestInvalidParameterThenError(TestRegisteredClients.registeredClient().build(),
				PkceParameterNames.CODE_CHALLENGE, OAuth2ErrorCodes.INVALID_REQUEST, (request) -> {
					request.addParameter(PkceParameterNames.CODE_CHALLENGE, "code-challenge");
					request.addParameter(PkceParameterNames.CODE_CHALLENGE, "another-code-challenge");
					updateQueryString(request);
				});
	}

	@Test
	public void doFilterWhenAuthorizationRequestMultipleCodeChallengeMethodThenInvalidRequestError() throws Exception {
		doFilterWhenAuthorizationRequestInvalidParameterThenError(TestRegisteredClients.registeredClient().build(),
				PkceParameterNames.CODE_CHALLENGE_METHOD, OAuth2ErrorCodes.INVALID_REQUEST, (request) -> {
					request.addParameter(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
					request.addParameter(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
					updateQueryString(request);
				});
	}

	@Test
	public void doFilterWhenAuthenticationRequestMultiplePromptThenInvalidRequestError() throws Exception {
		// Setup OpenID Connect request
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scopes((scopes) -> {
			scopes.clear();
			scopes.add(OidcScopes.OPENID);
		}).build();
		doFilterWhenAuthorizationRequestInvalidParameterThenError(registeredClient, "prompt",
				OAuth2ErrorCodes.INVALID_REQUEST, (request) -> {
					request.addParameter("prompt", "none");
					request.addParameter("prompt", "login");
					updateQueryString(request);
				});
	}

	@Test
	public void doFilterWhenAuthorizationRequestAuthenticationExceptionThenErrorResponse() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().redirectUris((redirectUris) -> {
			redirectUris.clear();
			redirectUris.add("https://example.com?param=encoded%20parameter%20value");
		}).build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal,
				registeredClient.getRedirectUris().iterator().next(), "client state", registeredClient.getScopes(),
				null);
		OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "error description", "error uri");
		given(this.authenticationManager.authenticate(any()))
			.willThrow(new OAuth2AuthorizationCodeRequestAuthenticationException(error,
					authorizationCodeRequestAuthentication));

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getRedirectedUrl()).isEqualTo(
				"https://example.com?param=encoded%20parameter%20value&error=invalid_request&error_description=error%20description&error_uri=error%20uri&state=client%20state");
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(this.principal);
	}

	@Test
	public void doFilterWhenCustomAuthenticationConverterThenUsed() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal,
				registeredClient.getRedirectUris().iterator().next(), STATE, registeredClient.getScopes(), null);

		AuthenticationConverter authenticationConverter = mock(AuthenticationConverter.class);
		given(authenticationConverter.convert(any())).willReturn(authorizationCodeRequestAuthentication);
		this.filter.setAuthenticationConverter(authenticationConverter);

		given(this.authenticationManager.authenticate(any())).willReturn(authorizationCodeRequestAuthentication);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(authenticationConverter).convert(any());
		verify(this.authenticationManager).authenticate(any());
		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenCustomAuthenticationSuccessHandlerThenUsed() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, this.authorizationCode,
				registeredClient.getRedirectUris().iterator().next(), STATE, registeredClient.getScopes());
		authorizationCodeRequestAuthenticationResult.setAuthenticated(true);
		given(this.authenticationManager.authenticate(any())).willReturn(authorizationCodeRequestAuthenticationResult);

		AuthenticationSuccessHandler authenticationSuccessHandler = mock(AuthenticationSuccessHandler.class);
		this.filter.setAuthenticationSuccessHandler(authenticationSuccessHandler);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);
		verify(authenticationSuccessHandler).onAuthenticationSuccess(any(), any(),
				same(authorizationCodeRequestAuthenticationResult));
	}

	@Test
	public void doFilterWhenCustomAuthenticationFailureHandlerThenUsed() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal,
				registeredClient.getRedirectUris().iterator().next(), STATE, registeredClient.getScopes(), null);
		OAuth2Error error = new OAuth2Error("errorCode", "errorDescription", "errorUri");
		OAuth2AuthorizationCodeRequestAuthenticationException authenticationException = new OAuth2AuthorizationCodeRequestAuthenticationException(
				error, authorizationCodeRequestAuthentication);
		given(this.authenticationManager.authenticate(any())).willThrow(authenticationException);

		AuthenticationFailureHandler authenticationFailureHandler = mock(AuthenticationFailureHandler.class);
		this.filter.setAuthenticationFailureHandler(authenticationFailureHandler);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);
		verify(authenticationFailureHandler).onAuthenticationFailure(any(), any(), same(authenticationException));
	}

	@Test
	public void doFilterWhenCustomSessionAuthenticationStrategyThenUsed() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, this.authorizationCode,
				registeredClient.getRedirectUris().iterator().next(), STATE, registeredClient.getScopes());
		authorizationCodeRequestAuthenticationResult.setAuthenticated(true);
		given(this.authenticationManager.authenticate(any())).willReturn(authorizationCodeRequestAuthenticationResult);

		SessionAuthenticationStrategy sessionAuthenticationStrategy = mock(SessionAuthenticationStrategy.class);
		this.filter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);
		verify(sessionAuthenticationStrategy).onAuthentication(same(authorizationCodeRequestAuthenticationResult),
				any(), any());
	}

	@Test
	public void doFilterWhenCustomAuthenticationDetailsSourceThenUsed() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal,
				registeredClient.getRedirectUris().iterator().next(), STATE, registeredClient.getScopes(), null);
		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);

		AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource = mock(
				AuthenticationDetailsSource.class);
		WebAuthenticationDetails webAuthenticationDetails = new WebAuthenticationDetails(request);
		given(authenticationDetailsSource.buildDetails(request)).willReturn(webAuthenticationDetails);
		this.filter.setAuthenticationDetailsSource(authenticationDetailsSource);

		given(this.authenticationManager.authenticate(any())).willReturn(authorizationCodeRequestAuthentication);

		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(authenticationDetailsSource).buildDetails(any());
		verify(this.authenticationManager).authenticate(any());
		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenAuthorizationRequestPrincipalNotAuthenticatedThenCommenceAuthentication() throws Exception {
		this.principal.setAuthenticated(false);
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal,
				registeredClient.getRedirectUris().iterator().next(), STATE, registeredClient.getScopes(), null);
		authorizationCodeRequestAuthenticationResult.setAuthenticated(false);
		given(this.authenticationManager.authenticate(any())).willReturn(authorizationCodeRequestAuthenticationResult);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenAuthorizationRequestConsentRequiredWithCustomConsentUriThenRedirectConsentResponse()
			throws Exception {
		Set<String> requestedScopes = new HashSet<>(Arrays.asList("scope1", "scope2"));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scopes((scopes) -> {
			scopes.clear();
			scopes.addAll(requestedScopes);
		}).build();
		// No scopes previously approved
		OAuth2AuthorizationConsentAuthenticationToken authorizationConsentAuthenticationResult = new OAuth2AuthorizationConsentAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, STATE, new HashSet<>(), null);
		authorizationConsentAuthenticationResult.setAuthenticated(true);
		given(this.authenticationManager.authenticate(any())).willReturn(authorizationConsentAuthenticationResult);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.setConsentPage("/oauth2/custom-consent");
		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getRedirectedUrl())
			.isEqualTo("http://localhost/oauth2/custom-consent?scope=scope1%20scope2&client_id=client-1&state=state");
	}

	@Test
	public void doFilterWhenAuthorizationRequestConsentRequiredThenConsentResponse() throws Exception {
		Set<String> requestedScopes = new HashSet<>(Arrays.asList("scope1", "scope2"));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scopes((scopes) -> {
			scopes.clear();
			scopes.addAll(requestedScopes);
		}).build();
		// No scopes previously approved
		OAuth2AuthorizationConsentAuthenticationToken authorizationConsentAuthenticationResult = new OAuth2AuthorizationConsentAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, STATE, new HashSet<>(), null);
		authorizationConsentAuthenticationResult.setAuthenticated(true);
		given(this.authenticationManager.authenticate(any())).willReturn(authorizationConsentAuthenticationResult);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
		assertThat(response.getContentType().equals(new MediaType("text", "html", StandardCharsets.UTF_8).toString()));
		for (String requestedScope : requestedScopes) {
			assertThat(response.getContentAsString()).contains(scopeCheckbox(requestedScope));
		}
	}

	@Test
	public void doFilterWhenAuthorizationRequestConsentRequiredWithPreviouslyApprovedThenConsentResponse()
			throws Exception {
		Set<String> approvedScopes = new HashSet<>(Arrays.asList("scope1", "scope2"));
		Set<String> requestedScopes = new HashSet<>(Arrays.asList("scope3", "scope4"));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scopes((scopes) -> {
			scopes.clear();
			scopes.addAll(approvedScopes);
			scopes.addAll(requestedScopes);
		}).build();
		OAuth2AuthorizationConsentAuthenticationToken authorizationConsentAuthenticationResult = new OAuth2AuthorizationConsentAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, STATE, approvedScopes, null);
		authorizationConsentAuthenticationResult.setAuthenticated(true);
		given(this.authenticationManager.authenticate(any())).willReturn(authorizationConsentAuthenticationResult);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
		assertThat(response.getContentType().equals(new MediaType("text", "html", StandardCharsets.UTF_8).toString()));
		for (String requestedScope : requestedScopes) {
			assertThat(response.getContentAsString()).contains(scopeCheckbox(requestedScope));
		}
		for (String approvedScope : approvedScopes) {
			assertThat(response.getContentAsString()).contains(disabledScopeCheckbox(approvedScope));
		}
	}

	@Test
	public void doFilterWhenAuthorizationRequestAuthenticatedThenAuthorizationResponse() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().redirectUris((redirectUris) -> {
			redirectUris.clear();
			redirectUris.add("https://example.com?param=encoded%20parameter%20value");
		}).build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, this.authorizationCode,
				registeredClient.getRedirectUris().iterator().next(), "client state", registeredClient.getScopes());
		authorizationCodeRequestAuthenticationResult.setAuthenticated(true);
		given(this.authenticationManager.authenticate(any())).willReturn(authorizationCodeRequestAuthenticationResult);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		request.addParameter("custom-param", "custom-value-1", "custom-value-2");
		updateQueryString(request);

		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		ArgumentCaptor<OAuth2AuthorizationCodeRequestAuthenticationToken> authorizationCodeRequestAuthenticationCaptor = ArgumentCaptor
			.forClass(OAuth2AuthorizationCodeRequestAuthenticationToken.class);
		verify(this.authenticationManager).authenticate(authorizationCodeRequestAuthenticationCaptor.capture());
		verifyNoInteractions(filterChain);

		assertThat(authorizationCodeRequestAuthenticationCaptor.getValue().getDetails())
			.asInstanceOf(InstanceOfAssertFactories.type(WebAuthenticationDetails.class))
			.extracting(WebAuthenticationDetails::getRemoteAddress)
			.isEqualTo(REMOTE_ADDRESS);

		// Assert that multi-valued request parameters are preserved
		assertThat(authorizationCodeRequestAuthenticationCaptor.getValue().getAdditionalParameters())
			.extracting((params) -> params.get("custom-param"))
			.asInstanceOf(InstanceOfAssertFactories.type(String[].class))
			.isEqualTo(new String[] { "custom-value-1", "custom-value-2" });
		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getRedirectedUrl())
			.isEqualTo("https://example.com?param=encoded%20parameter%20value&code=code&state=client%20state");
	}

	@Test
	public void doFilterWhenPostAuthorizationRequestAuthenticatedThenAuthorizationResponse() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().redirectUris((redirectUris) -> {
			redirectUris.clear();
			redirectUris.add("https://example.com?param=encoded%20parameter%20value");
		}).build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, this.authorizationCode,
				registeredClient.getRedirectUris().iterator().next(), "client state", registeredClient.getScopes());
		authorizationCodeRequestAuthenticationResult.setAuthenticated(true);
		given(this.authenticationManager.authenticate(any())).willReturn(authorizationCodeRequestAuthenticationResult);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		request.setMethod("POST");
		request.setQueryString(null);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getRedirectedUrl())
			.isEqualTo("https://example.com?param=encoded%20parameter%20value&code=code&state=client%20state");
	}

	@Test
	public void doFilterWhenAuthenticationRequestAuthenticatedThenAuthorizationResponse() throws Exception {
		// Setup OpenID Connect request
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scopes((scopes) -> {
			scopes.clear();
			scopes.add(OidcScopes.OPENID);
		}).build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.principal, this.authorizationCode,
				registeredClient.getRedirectUris().iterator().next(), STATE, registeredClient.getScopes());
		authorizationCodeRequestAuthenticationResult.setAuthenticated(true);
		given(this.authenticationManager.authenticate(any())).willReturn(authorizationCodeRequestAuthenticationResult);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		request.setMethod("POST"); // OpenID Connect supports POST method
		request.setQueryString(null);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getRedirectedUrl())
			.isEqualTo(request.getParameter(OAuth2ParameterNames.REDIRECT_URI) + "?code=code&state=state");
	}

	private void doFilterWhenAuthorizationRequestInvalidParameterThenError(RegisteredClient registeredClient,
			String parameterName, String errorCode, Consumer<MockHttpServletRequest> requestConsumer) throws Exception {

		doFilterWhenRequestInvalidParameterThenError(createAuthorizationRequest(registeredClient), parameterName,
				errorCode, requestConsumer);
	}

	private void doFilterWhenAuthorizationConsentRequestInvalidParameterThenError(RegisteredClient registeredClient,
			String parameterName, String errorCode, Consumer<MockHttpServletRequest> requestConsumer) throws Exception {

		doFilterWhenRequestInvalidParameterThenError(createAuthorizationConsentRequest(registeredClient), parameterName,
				errorCode, requestConsumer);
	}

	private void doFilterWhenRequestInvalidParameterThenError(MockHttpServletRequest request, String parameterName,
			String errorCode, Consumer<MockHttpServletRequest> requestConsumer) throws Exception {

		requestConsumer.accept(request);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		assertThat(response.getErrorMessage()).isEqualTo("[" + errorCode + "] OAuth 2.0 Parameter: " + parameterName);
	}

	private static MockHttpServletRequest createAuthorizationRequest(RegisteredClient registeredClient) {
		String requestUri = DEFAULT_AUTHORIZATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		request.setRemoteAddr(REMOTE_ADDRESS);

		request.addParameter(OAuth2ParameterNames.RESPONSE_TYPE, OAuth2AuthorizationResponseType.CODE.getValue());
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		request.addParameter(OAuth2ParameterNames.REDIRECT_URI, registeredClient.getRedirectUris().iterator().next());
		request.addParameter(OAuth2ParameterNames.SCOPE,
				StringUtils.collectionToDelimitedString(registeredClient.getScopes(), " "));
		request.addParameter(OAuth2ParameterNames.STATE, "state");
		updateQueryString(request);

		return request;
	}

	private static MockHttpServletRequest createAuthorizationConsentRequest(RegisteredClient registeredClient) {
		String requestUri = DEFAULT_AUTHORIZATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		request.setRemoteAddr(REMOTE_ADDRESS);

		request.addParameter(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		registeredClient.getScopes().forEach((scope) -> request.addParameter(OAuth2ParameterNames.SCOPE, scope));
		request.addParameter(OAuth2ParameterNames.STATE, "state");

		return request;
	}

	private static void updateQueryString(MockHttpServletRequest request) {
		UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(request.getRequestURI());
		request.getParameterMap().forEach((key, values) -> {
			if (values.length > 0) {
				for (String value : values) {
					uriBuilder.queryParam(key, value);
				}
			}
		});
		request.setQueryString(uriBuilder.build().getQuery());
	}

	private static String scopeCheckbox(String scope) {
		return MessageFormat.format(
				"<input class=\"form-check-input\" type=\"checkbox\" name=\"scope\" value=\"{0}\" id=\"{0}\">", scope);
	}

	private static String disabledScopeCheckbox(String scope) {
		return MessageFormat.format(
				"<input class=\"form-check-input\" type=\"checkbox\" name=\"scope\" id=\"{0}\" checked disabled>",
				scope);
	}

}
