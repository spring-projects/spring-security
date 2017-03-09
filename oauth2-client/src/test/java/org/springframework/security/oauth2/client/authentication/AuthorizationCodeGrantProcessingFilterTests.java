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
import org.springframework.security.oauth2.client.authorization.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.authorization.HttpSessionAuthorizationRequestRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2Attributes;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.protocol.AuthorizationRequestAttributes;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.security.oauth2.client.ClientRegistrationTestUtil.*;

/**
 * Tests {@link AuthorizationCodeGrantProcessingFilter}.
 *
 * @author Joe Grandja
 */
public class AuthorizationCodeGrantProcessingFilterTests {

	@Test(expected = IllegalArgumentException.class)
	public void afterPropertiesSetWhenClientRegistrationRepositoryIsNullThenThrowIllegalArgumentException() {
		AuthorizationCodeGrantProcessingFilter filter = new AuthorizationCodeGrantProcessingFilter();
		filter.setAuthenticationManager(mock(AuthenticationManager.class));
		filter.afterPropertiesSet();
	}

	@Test(expected = IllegalArgumentException.class)
	public void afterPropertiesSetWhenAuthenticationManagerIsNullThenThrowIllegalArgumentException() {
		AuthorizationCodeGrantProcessingFilter filter = new AuthorizationCodeGrantProcessingFilter();
		filter.setClientRegistrationRepository(mock(ClientRegistrationRepository.class));
		filter.afterPropertiesSet();
	}

	@Test
	public void doFilterWhenNotAuthorizationCodeGrantResponseThenContinueChain() throws Exception {
		ClientRegistration clientRegistration = googleClientRegistration();

		AuthorizationCodeGrantProcessingFilter filter = spy(setupFilter(clientRegistration));

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
	public void doFilterWhenAuthorizationCodeGrantErrorResponseThenAuthenticationFailureHandlerIsCalled() throws Exception {
		ClientRegistration clientRegistration = githubClientRegistration();

		AuthorizationCodeGrantProcessingFilter filter = spy(setupFilter(clientRegistration));
		AuthenticationFailureHandler failureHandler = mock(AuthenticationFailureHandler.class);
		filter.setAuthenticationFailureHandler(failureHandler);

		String requestURI = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestURI);
		request.setServletPath(requestURI);
		String errorCode = OAuth2Error.ErrorCode.INVALID_GRANT.toString();
		request.addParameter(OAuth2Attributes.ERROR, errorCode);
		request.addParameter(OAuth2Attributes.STATE, "some state");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verify(filter).attemptAuthentication(any(HttpServletRequest.class), any(HttpServletResponse.class));
		verify(failureHandler).onAuthenticationFailure(any(HttpServletRequest.class), any(HttpServletResponse.class),
				any(AuthenticationException.class));
	}

	@Test
	public void doFilterWhenAuthorizationCodeGrantSuccessResponseThenAuthenticationSuccessHandlerIsCalled() throws Exception {
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("joe", "password", "user", "admin");
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
		when(authenticationManager.authenticate(any(Authentication.class))).thenReturn(authentication);

		String requestURI = "/path";
		ClientRegistration clientRegistration = githubClientRegistration(requestURI);	// requestUri must be same as client redirectUri to pass validation

		AuthorizationCodeGrantProcessingFilter filter = spy(setupFilter(authenticationManager, clientRegistration));
		AuthenticationSuccessHandler successHandler = mock(AuthenticationSuccessHandler.class);
		filter.setAuthenticationSuccessHandler(successHandler);
		AuthorizationRequestRepository authorizationRequestRepository = new HttpSessionAuthorizationRequestRepository();
		filter.setAuthorizationRequestRepository(authorizationRequestRepository);

		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestURI);
		request.setServletPath(requestURI);
		String authCode = "some code";
		String state = "some state";
		request.addParameter(OAuth2Attributes.CODE, authCode);
		request.addParameter(OAuth2Attributes.STATE, state);
		setupAuthorizationRequest(authorizationRequestRepository, request, clientRegistration, state);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verify(filter).attemptAuthentication(any(HttpServletRequest.class), any(HttpServletResponse.class));

		ArgumentCaptor<Authentication> authenticationArgCaptor = ArgumentCaptor.forClass(Authentication.class);
		verify(successHandler).onAuthenticationSuccess(any(HttpServletRequest.class), any(HttpServletResponse.class),
				authenticationArgCaptor.capture());
		assertThat(authenticationArgCaptor.getValue()).isEqualTo(authentication);
	}

	@Test
	public void doFilterWhenAuthorizationCodeGrantSuccessResponseAndNoMatchingAuthorizationRequestThenThrowOAuth2AuthenticationExceptionAuthorizationRequestNotFound() throws Exception {
		ClientRegistration clientRegistration = githubClientRegistration();

		AuthorizationCodeGrantProcessingFilter filter = spy(setupFilter(clientRegistration));
		AuthenticationFailureHandler failureHandler = mock(AuthenticationFailureHandler.class);
		filter.setAuthenticationFailureHandler(failureHandler);

		String requestURI = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestURI);
		request.setServletPath(requestURI);
		String authCode = "some code";
		String state = "some state";
		request.addParameter(OAuth2Attributes.CODE, authCode);
		request.addParameter(OAuth2Attributes.STATE, state);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verifyThrowsOAuth2AuthenticationExceptionWithErrorCode(filter, failureHandler, OAuth2Error.ErrorCode.AUTHORIZATION_REQUEST_NOT_FOUND);
	}

	@Test
	public void doFilterWhenAuthorizationCodeGrantSuccessResponseWithInvalidStateParamThenThrowOAuth2AuthenticationExceptionInvalidStateParameter() throws Exception {
		ClientRegistration clientRegistration = githubClientRegistration();

		AuthorizationCodeGrantProcessingFilter filter = spy(setupFilter(clientRegistration));
		AuthenticationFailureHandler failureHandler = mock(AuthenticationFailureHandler.class);
		filter.setAuthenticationFailureHandler(failureHandler);
		AuthorizationRequestRepository authorizationRequestRepository = new HttpSessionAuthorizationRequestRepository();
		filter.setAuthorizationRequestRepository(authorizationRequestRepository);

		String requestURI = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestURI);
		request.setServletPath(requestURI);
		String authCode = "some code";
		String state = "some other state";
		request.addParameter(OAuth2Attributes.CODE, authCode);
		request.addParameter(OAuth2Attributes.STATE, state);
		setupAuthorizationRequest(authorizationRequestRepository, request, clientRegistration, "some state");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verifyThrowsOAuth2AuthenticationExceptionWithErrorCode(filter, failureHandler, OAuth2Error.ErrorCode.INVALID_STATE_PARAMETER);
	}

	@Test
	public void doFilterWhenAuthorizationCodeGrantSuccessResponseWithInvalidRedirectUriParamThenThrowOAuth2AuthenticationExceptionInvalidRedirectUriParameter() throws Exception {
		String requestURI = "/path2";
		ClientRegistration clientRegistration = githubClientRegistration("/path");

		AuthorizationCodeGrantProcessingFilter filter = spy(setupFilter(clientRegistration));
		AuthenticationFailureHandler failureHandler = mock(AuthenticationFailureHandler.class);
		filter.setAuthenticationFailureHandler(failureHandler);
		AuthorizationRequestRepository authorizationRequestRepository = new HttpSessionAuthorizationRequestRepository();
		filter.setAuthorizationRequestRepository(authorizationRequestRepository);

		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestURI);
		request.setServletPath(requestURI);
		String authCode = "some code";
		String state = "some state";
		request.addParameter(OAuth2Attributes.CODE, authCode);
		request.addParameter(OAuth2Attributes.STATE, state);
		setupAuthorizationRequest(authorizationRequestRepository, request, clientRegistration, state);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verifyThrowsOAuth2AuthenticationExceptionWithErrorCode(filter, failureHandler, OAuth2Error.ErrorCode.INVALID_REDIRECT_URI_PARAMETER);
	}

	private void verifyThrowsOAuth2AuthenticationExceptionWithErrorCode(AuthorizationCodeGrantProcessingFilter filter,
																		AuthenticationFailureHandler failureHandler,
																		OAuth2Error.ErrorCode errorCode) throws Exception {

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

	private AuthorizationCodeGrantProcessingFilter setupFilter(ClientRegistration... clientRegistrations) throws Exception {
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);

		return setupFilter(authenticationManager, clientRegistrations);
	}

	private AuthorizationCodeGrantProcessingFilter setupFilter(
			AuthenticationManager authenticationManager, ClientRegistration... clientRegistrations) throws Exception {

		ClientRegistrationRepository clientRegistrationRepository = clientRegistrationRepository(clientRegistrations);

		AuthorizationCodeGrantProcessingFilter filter = new AuthorizationCodeGrantProcessingFilter();
		filter.setClientRegistrationRepository(clientRegistrationRepository);
		filter.setAuthenticationManager(authenticationManager);
		filter.afterPropertiesSet();

		return filter;
	}

	private void setupAuthorizationRequest(AuthorizationRequestRepository authorizationRequestRepository,
											HttpServletRequest request,
											ClientRegistration clientRegistration,
											String state) {

		AuthorizationRequestAttributes authorizationRequestAttributes =
				AuthorizationRequestAttributes.authorizationCodeGrant(
						clientRegistration.getProviderDetails().getAuthorizationUri(),
						clientRegistration.getClientId(),
						clientRegistration.getRedirectUri(),
						clientRegistration.getScopes(),
						state);

		authorizationRequestRepository.saveAuthorizationRequest(authorizationRequestAttributes, request);
	}
}
