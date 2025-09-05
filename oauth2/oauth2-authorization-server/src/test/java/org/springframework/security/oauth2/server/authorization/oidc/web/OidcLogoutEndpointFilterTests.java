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

package org.springframework.security.oauth2.server.authorization.oidc.web;

import java.util.function.Consumer;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link OidcLogoutEndpointFilter}.
 *
 * @author Joe Grandja
 */
public class OidcLogoutEndpointFilterTests {

	private static final String DEFAULT_OIDC_LOGOUT_ENDPOINT_URI = "/connect/logout";

	private AuthenticationManager authenticationManager;

	private OidcLogoutEndpointFilter filter;

	private TestingAuthenticationToken principal;

	@BeforeEach
	public void setUp() {
		this.authenticationManager = mock(AuthenticationManager.class);
		this.filter = new OidcLogoutEndpointFilter(this.authenticationManager);
		this.principal = new TestingAuthenticationToken("principal", "credentials");
		this.principal.setAuthenticated(true);
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(this.principal);
		SecurityContextHolder.setContext(securityContext);
	}

	@AfterEach
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void constructorWhenAuthenticationManagerNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> new OidcLogoutEndpointFilter(null))
			.withMessage("authenticationManager cannot be null");
	}

	@Test
	public void constructorWhenLogoutEndpointUriNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> new OidcLogoutEndpointFilter(this.authenticationManager, null))
			.withMessage("logoutEndpointUri cannot be empty");
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
	public void doFilterWhenNotLogoutRequestThenNotProcessed() throws Exception {
		String requestUri = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenLogoutRequestMissingIdTokenHintThenInvalidRequestError() throws Exception {
		doFilterWhenRequestInvalidParameterThenError(
				createLogoutRequest(TestRegisteredClients.registeredClient().build()), "id_token_hint",
				OAuth2ErrorCodes.INVALID_REQUEST, (request) -> request.removeParameter("id_token_hint"));
	}

	@Test
	public void doFilterWhenLogoutRequestMultipleIdTokenHintThenInvalidRequestError() throws Exception {
		doFilterWhenRequestInvalidParameterThenError(
				createLogoutRequest(TestRegisteredClients.registeredClient().build()), "id_token_hint",
				OAuth2ErrorCodes.INVALID_REQUEST, (request) -> request.addParameter("id_token_hint", "id-token-2"));
	}

	@Test
	public void doFilterWhenLogoutRequestMultipleClientIdThenInvalidRequestError() throws Exception {
		doFilterWhenRequestInvalidParameterThenError(
				createLogoutRequest(TestRegisteredClients.registeredClient().build()), OAuth2ParameterNames.CLIENT_ID,
				OAuth2ErrorCodes.INVALID_REQUEST,
				(request) -> request.addParameter(OAuth2ParameterNames.CLIENT_ID, "client-2"));
	}

	@Test
	public void doFilterWhenLogoutRequestMultiplePostLogoutRedirectUriThenInvalidRequestError() throws Exception {
		doFilterWhenRequestInvalidParameterThenError(
				createLogoutRequest(TestRegisteredClients.registeredClient().build()), "post_logout_redirect_uri",
				OAuth2ErrorCodes.INVALID_REQUEST,
				(request) -> request.addParameter("post_logout_redirect_uri", "https://example.com/callback-4"));
	}

	@Test
	public void doFilterWhenLogoutRequestMultipleStateThenInvalidRequestError() throws Exception {
		doFilterWhenRequestInvalidParameterThenError(
				createLogoutRequest(TestRegisteredClients.registeredClient().build()), OAuth2ParameterNames.STATE,
				OAuth2ErrorCodes.INVALID_REQUEST,
				(request) -> request.addParameter(OAuth2ParameterNames.STATE, "state-2"));
	}

	private void doFilterWhenRequestInvalidParameterThenError(MockHttpServletRequest request, String parameterName,
			String errorCode, Consumer<MockHttpServletRequest> requestConsumer) throws Exception {

		requestConsumer.accept(request);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		assertThat(response.getErrorMessage())
			.isEqualTo("[" + errorCode + "] OpenID Connect 1.0 Logout Request Parameter: " + parameterName);
	}

	@Test
	public void doFilterWhenLogoutRequestAuthenticationExceptionThenErrorResponse() throws Exception {
		OAuth2Error error = new OAuth2Error("errorCode", "errorDescription", "errorUri");
		given(this.authenticationManager.authenticate(any())).willThrow(new OAuth2AuthenticationException(error));

		MockHttpServletRequest request = createLogoutRequest(TestRegisteredClients.registeredClient().build());
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		assertThat(response.getErrorMessage()).isEqualTo(error.toString());
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(this.principal);
	}

	@Test
	public void doFilterWhenCustomAuthenticationConverterThenUsed() throws Exception {
		OidcLogoutAuthenticationToken authentication = new OidcLogoutAuthenticationToken("id-token", this.principal,
				null, null, null, null);

		AuthenticationConverter authenticationConverter = mock(AuthenticationConverter.class);
		given(authenticationConverter.convert(any())).willReturn((authentication));
		this.filter.setAuthenticationConverter(authenticationConverter);

		given(this.authenticationManager.authenticate(any())).willReturn((authentication));

		MockHttpServletRequest request = createLogoutRequest(TestRegisteredClients.registeredClient().build());
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(authenticationConverter).convert(any());
		verify(this.authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);
	}

	@Test
	public void doFilterWhenCustomAuthenticationSuccessHandlerThenUsed() throws Exception {
		OidcLogoutAuthenticationToken authentication = new OidcLogoutAuthenticationToken("id-token", this.principal,
				null, null, null, null);

		AuthenticationSuccessHandler authenticationSuccessHandler = mock(AuthenticationSuccessHandler.class);
		this.filter.setAuthenticationSuccessHandler(authenticationSuccessHandler);

		given(this.authenticationManager.authenticate(any())).willReturn((authentication));

		MockHttpServletRequest request = createLogoutRequest(TestRegisteredClients.registeredClient().build());
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verify(authenticationSuccessHandler).onAuthenticationSuccess(any(), any(), same(authentication));
		verifyNoInteractions(filterChain);
	}

	@Test
	public void doFilterWhenCustomAuthenticationFailureHandlerThenUsed() throws Exception {
		AuthenticationFailureHandler authenticationFailureHandler = mock(AuthenticationFailureHandler.class);
		this.filter.setAuthenticationFailureHandler(authenticationFailureHandler);

		given(this.authenticationManager.authenticate(any()))
			.willThrow(new AuthenticationServiceException("AuthenticationServiceException"));

		MockHttpServletRequest request = createLogoutRequest(TestRegisteredClients.registeredClient().build());
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		ArgumentCaptor<AuthenticationException> authenticationExceptionCaptor = ArgumentCaptor
			.forClass(AuthenticationException.class);
		verify(this.authenticationManager).authenticate(any());
		verify(authenticationFailureHandler).onAuthenticationFailure(any(), any(),
				authenticationExceptionCaptor.capture());
		verifyNoInteractions(filterChain);

		assertThat(authenticationExceptionCaptor.getValue()).isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
				assertThat(error.getDescription()).contains("AuthenticationServiceException");
			});
	}

	@Test
	public void doFilterWhenLogoutRequestAuthenticatedThenLogout() throws Exception {
		MockHttpServletRequest request = createLogoutRequest(TestRegisteredClients.registeredClient().build());
		MockHttpSession session = (MockHttpSession) request.getSession(true);

		OidcLogoutAuthenticationToken authentication = new OidcLogoutAuthenticationToken("id-token", this.principal,
				session.getId(), null, null, null);

		given(this.authenticationManager.authenticate(any())).willReturn((authentication));

		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getRedirectedUrl()).isEqualTo("/");
		assertThat(session.isInvalid()).isTrue();
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void doFilterWhenLogoutRequestAuthenticatedWithPostLogoutRedirectUriThenPostLogoutRedirect()
			throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		MockHttpServletRequest request = createLogoutRequest(registeredClient);
		MockHttpSession session = (MockHttpSession) request.getSession(true);

		String postLogoutRedirectUri = registeredClient.getPostLogoutRedirectUris().iterator().next();
		String state = "state-1";
		OidcLogoutAuthenticationToken authentication = new OidcLogoutAuthenticationToken("id-token", this.principal,
				session.getId(), registeredClient.getClientId(), postLogoutRedirectUri, state);
		authentication.setAuthenticated(true);

		given(this.authenticationManager.authenticate(any())).willReturn((authentication));

		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getRedirectedUrl()).isEqualTo(postLogoutRedirectUri + "?state=" + state);
		assertThat(session.isInvalid()).isTrue();
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	private static MockHttpServletRequest createLogoutRequest(RegisteredClient registeredClient) {
		String requestUri = DEFAULT_OIDC_LOGOUT_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);

		request.addParameter("id_token_hint", "id-token");
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		request.addParameter("post_logout_redirect_uri",
				registeredClient.getPostLogoutRedirectUris().iterator().next());
		request.addParameter(OAuth2ParameterNames.STATE, "state");

		return request;
	}

}
