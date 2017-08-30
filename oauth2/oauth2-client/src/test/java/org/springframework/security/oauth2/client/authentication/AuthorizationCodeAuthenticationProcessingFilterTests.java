/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.authentication;

import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.AuthorizationRequestAttributes;
import org.springframework.security.oauth2.core.endpoint.OAuth2Parameter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.security.oauth2.client.authentication.TestUtil.*;

/**
 * Tests {@link AuthorizationCodeAuthenticationProcessingFilter}.
 *
 * @author Joe Grandja
 */
public class AuthorizationCodeAuthenticationProcessingFilterTests {

	@Test
	public void doFilterWhenNotAuthorizationCodeResponseThenContinueChain() throws Exception {
		ClientRegistration clientRegistration = googleClientRegistration();

		AuthorizationCodeAuthenticationProcessingFilter filter = spy(setupFilter(clientRegistration));

		String requestURI = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestURI);
		request.setServletPath(requestURI);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		verify(filter, never()).attemptAuthentication(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenAuthorizationCodeErrorResponseThenAuthenticationFailureHandlerIsCalled() throws Exception {
		ClientRegistration clientRegistration = githubClientRegistration();

		AuthorizationCodeAuthenticationProcessingFilter filter = spy(setupFilter(clientRegistration));
		AuthenticationFailureHandler failureHandler = mock(AuthenticationFailureHandler.class);
		filter.setAuthenticationFailureHandler(failureHandler);

		MockHttpServletRequest request = this.setupRequest(clientRegistration);
		String errorCode = OAuth2Error.INVALID_GRANT_ERROR_CODE;
		request.addParameter(OAuth2Parameter.ERROR, errorCode);
		request.addParameter(OAuth2Parameter.STATE, "some state");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verify(filter).attemptAuthentication(any(HttpServletRequest.class), any(HttpServletResponse.class));
		verify(failureHandler).onAuthenticationFailure(any(HttpServletRequest.class), any(HttpServletResponse.class),
				any(AuthenticationException.class));
	}

	@Test
	public void doFilterWhenAuthorizationCodeSuccessResponseThenAuthenticationSuccessHandlerIsCalled() throws Exception {
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("joe", "password", "user", "admin");
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
		when(authenticationManager.authenticate(any(Authentication.class))).thenReturn(authentication);

		ClientRegistration clientRegistration = githubClientRegistration();

		AuthorizationCodeAuthenticationProcessingFilter filter = spy(setupFilter(authenticationManager, clientRegistration));
		AuthenticationSuccessHandler successHandler = mock(AuthenticationSuccessHandler.class);
		filter.setAuthenticationSuccessHandler(successHandler);
		AuthorizationRequestRepository authorizationRequestRepository = new HttpSessionAuthorizationRequestRepository();
		filter.setAuthorizationRequestRepository(authorizationRequestRepository);

		MockHttpServletRequest request = this.setupRequest(clientRegistration);
		String authCode = "some code";
		String state = "some state";
		request.addParameter(OAuth2Parameter.CODE, authCode);
		request.addParameter(OAuth2Parameter.STATE, state);
		MockHttpServletResponse response = new MockHttpServletResponse();
		setupAuthorizationRequest(authorizationRequestRepository, request, response, clientRegistration, state);
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verify(filter).attemptAuthentication(any(HttpServletRequest.class), any(HttpServletResponse.class));

		ArgumentCaptor<Authentication> authenticationArgCaptor = ArgumentCaptor.forClass(Authentication.class);
		verify(successHandler).onAuthenticationSuccess(any(HttpServletRequest.class), any(HttpServletResponse.class),
				authenticationArgCaptor.capture());
		assertThat(authenticationArgCaptor.getValue()).isEqualTo(authentication);
	}

	@Test
	public void doFilterWhenAuthorizationCodeSuccessResponseAndNoMatchingAuthorizationRequestThenThrowOAuth2AuthenticationExceptionAuthorizationRequestNotFound() throws Exception {
		ClientRegistration clientRegistration = githubClientRegistration();

		AuthorizationCodeAuthenticationProcessingFilter filter = spy(setupFilter(clientRegistration));
		AuthenticationFailureHandler failureHandler = mock(AuthenticationFailureHandler.class);
		filter.setAuthenticationFailureHandler(failureHandler);

		MockHttpServletRequest request = this.setupRequest(clientRegistration);
		String authCode = "some code";
		String state = "some state";
		request.addParameter(OAuth2Parameter.CODE, authCode);
		request.addParameter(OAuth2Parameter.STATE, state);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verifyThrowsOAuth2AuthenticationExceptionWithErrorCode(filter, failureHandler, "authorization_request_not_found");
	}

	@Test
	public void doFilterWhenAuthorizationCodeSuccessResponseWithInvalidStateParamThenThrowOAuth2AuthenticationExceptionInvalidStateParameter() throws Exception {
		ClientRegistration clientRegistration = githubClientRegistration();

		AuthorizationCodeAuthenticationProcessingFilter filter = spy(setupFilter(clientRegistration));
		AuthenticationFailureHandler failureHandler = mock(AuthenticationFailureHandler.class);
		filter.setAuthenticationFailureHandler(failureHandler);
		AuthorizationRequestRepository authorizationRequestRepository = new HttpSessionAuthorizationRequestRepository();
		filter.setAuthorizationRequestRepository(authorizationRequestRepository);

		MockHttpServletRequest request = this.setupRequest(clientRegistration);
		String authCode = "some code";
		String state = "some other state";
		request.addParameter(OAuth2Parameter.CODE, authCode);
		request.addParameter(OAuth2Parameter.STATE, state);
		MockHttpServletResponse response = new MockHttpServletResponse();
		setupAuthorizationRequest(authorizationRequestRepository, request, response, clientRegistration, "some state");
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verifyThrowsOAuth2AuthenticationExceptionWithErrorCode(filter, failureHandler, "invalid_state_parameter");
	}

	@Test
	public void doFilterWhenAuthorizationCodeSuccessResponseWithInvalidRedirectUriParamThenThrowOAuth2AuthenticationExceptionInvalidRedirectUriParameter() throws Exception {
		ClientRegistration clientRegistration = githubClientRegistration();

		AuthorizationCodeAuthenticationProcessingFilter filter = spy(setupFilter(clientRegistration));
		AuthenticationFailureHandler failureHandler = mock(AuthenticationFailureHandler.class);
		filter.setAuthenticationFailureHandler(failureHandler);
		AuthorizationRequestRepository authorizationRequestRepository = new HttpSessionAuthorizationRequestRepository();
		filter.setAuthorizationRequestRepository(authorizationRequestRepository);

		MockHttpServletRequest request = this.setupRequest(clientRegistration);
		request.setRequestURI(request.getRequestURI() + "-other");
		String authCode = "some code";
		String state = "some state";
		request.addParameter(OAuth2Parameter.CODE, authCode);
		request.addParameter(OAuth2Parameter.STATE, state);
		MockHttpServletResponse response = new MockHttpServletResponse();
		setupAuthorizationRequest(authorizationRequestRepository, request, response, clientRegistration, state);
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verifyThrowsOAuth2AuthenticationExceptionWithErrorCode(filter, failureHandler, "invalid_redirect_uri_parameter");
	}

	private void verifyThrowsOAuth2AuthenticationExceptionWithErrorCode(AuthorizationCodeAuthenticationProcessingFilter filter,
																		AuthenticationFailureHandler failureHandler,
																		String errorCode) throws Exception {

		verify(filter).attemptAuthentication(any(HttpServletRequest.class), any(HttpServletResponse.class));

		ArgumentCaptor<AuthenticationException> authenticationExceptionArgCaptor =
				ArgumentCaptor.forClass(AuthenticationException.class);
		verify(failureHandler).onAuthenticationFailure(any(HttpServletRequest.class), any(HttpServletResponse.class),
				authenticationExceptionArgCaptor.capture());
		assertThat(authenticationExceptionArgCaptor.getValue()).isInstanceOf(OAuth2AuthenticationException.class);
		OAuth2AuthenticationException oauth2AuthenticationException =
				(OAuth2AuthenticationException)authenticationExceptionArgCaptor.getValue();
		assertThat(oauth2AuthenticationException.getErrorObject()).isNotNull();
		assertThat(oauth2AuthenticationException.getErrorObject().getErrorCode()).isEqualTo(errorCode);
	}

	private AuthorizationCodeAuthenticationProcessingFilter setupFilter(ClientRegistration... clientRegistrations) throws Exception {
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);

		return setupFilter(authenticationManager, clientRegistrations);
	}

	private AuthorizationCodeAuthenticationProcessingFilter setupFilter(
			AuthenticationManager authenticationManager, ClientRegistration... clientRegistrations) throws Exception {

		ClientRegistrationRepository clientRegistrationRepository = clientRegistrationRepository(clientRegistrations);

		AuthorizationCodeAuthenticationProcessingFilter filter = new AuthorizationCodeAuthenticationProcessingFilter();
		filter.setClientRegistrationRepository(clientRegistrationRepository);
		filter.setAuthenticationManager(authenticationManager);

		return filter;
	}

	private void setupAuthorizationRequest(AuthorizationRequestRepository authorizationRequestRepository,
											HttpServletRequest request,
										    HttpServletResponse response,
											ClientRegistration clientRegistration,
											String state) {

		AuthorizationRequestAttributes authorizationRequestAttributes =
			AuthorizationRequestAttributes.withAuthorizationCode()
				.clientId(clientRegistration.getClientId())
				.authorizeUri(clientRegistration.getProviderDetails().getAuthorizationUri())
				.redirectUri(clientRegistration.getRedirectUri())
				.scope(clientRegistration.getScope())
				.state(state)
				.build();

		authorizationRequestRepository.saveAuthorizationRequest(authorizationRequestAttributes, request, response);
	}

	private MockHttpServletRequest setupRequest(ClientRegistration clientRegistration) {
		String requestURI = AUTHORIZE_BASE_URI + "/" + clientRegistration.getClientAlias();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestURI);
		request.setScheme(DEFAULT_SCHEME);
		request.setServerName(DEFAULT_SERVER_NAME);
		request.setServerPort(DEFAULT_SERVER_PORT);
		request.setServletPath(requestURI);
		return request;
	}
}
