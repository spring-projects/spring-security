/*
 * Copyright 2020-2025 the original author or authors.
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

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2DeviceAuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2DeviceAuthorizationResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceAuthorizationRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.context.TestAuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link OAuth2DeviceAuthorizationEndpointFilter}.
 *
 * @author Steve Riesenberg
 */
public class OAuth2DeviceAuthorizationEndpointFilterTests {

	private static final String ISSUER_URI = "https://provider.com:8090";

	private static final String REMOTE_ADDRESS = "remote-address";

	private static final String AUTHORIZATION_URI = "/oauth2/device_authorization";

	private static final String VERIFICATION_URI = "/oauth2/device_verification";

	private static final String CLIENT_ID = "client-1";

	private static final String DEVICE_CODE = "EfYu_0jEL";

	private static final String USER_CODE = "BCDF-GHJK";

	private AuthenticationManager authenticationManager;

	private OAuth2DeviceAuthorizationEndpointFilter filter;

	private final HttpMessageConverter<OAuth2DeviceAuthorizationResponse> deviceAuthorizationHttpResponseConverter = new OAuth2DeviceAuthorizationResponseHttpMessageConverter();

	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter = new OAuth2ErrorHttpMessageConverter();

	@BeforeEach
	public void setUp() {
		this.authenticationManager = mock(AuthenticationManager.class);
		this.filter = new OAuth2DeviceAuthorizationEndpointFilter(this.authenticationManager);
		mockAuthorizationServerContext();
	}

	@AfterEach
	public void tearDown() {
		SecurityContextHolder.clearContext();
		AuthorizationServerContextHolder.resetContext();
	}

	@Test
	public void constructorWhenAuthenticationMangerIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2DeviceAuthorizationEndpointFilter(null))
				.withMessage("authenticationManager cannot be null");
		// @formatter:on
	}

	@Test
	public void constructorWhenDeviceAuthorizationEndpointUriIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2DeviceAuthorizationEndpointFilter(this.authenticationManager, null))
				.withMessage("deviceAuthorizationEndpointUri cannot be empty");
		// @formatter:on
	}

	@Test
	public void setAuthenticationConverterWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.filter.setAuthenticationConverter(null))
				.withMessage("authenticationConverter cannot be null");
		// @formatter:on
	}

	@Test
	public void setAuthenticationDetailsSourceWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.filter.setAuthenticationDetailsSource(null))
				.withMessage("authenticationDetailsSource cannot be null");
		// @formatter:on
	}

	@Test
	public void setAuthenticationSuccessHandlerWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.filter.setAuthenticationSuccessHandler(null))
				.withMessage("authenticationSuccessHandler cannot be null");
		// @formatter:on
	}

	@Test
	public void setAuthenticationFailureHandlerWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.filter.setAuthenticationFailureHandler(null))
				.withMessage("authenticationFailureHandler cannot be null");
		// @formatter:on
	}

	@Test
	public void setVerificationUriWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.filter.setVerificationUri(null))
				.withMessage("verificationUri cannot be empty");
		// @formatter:on
	}

	@Test
	public void doFilterWhenNotDeviceAuthorizationRequestThenNotProcessed() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), "/path");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.filter.doFilter(request, response, filterChain);
		verify(filterChain).doFilter(request, response);
		verifyNoInteractions(this.authenticationManager);
	}

	@Test
	public void doFilterWhenDeviceAuthorizationRequestGetThenNotProcessed() throws Exception {
		MockHttpServletRequest request = createRequest();
		request.setMethod(HttpMethod.GET.name());
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.filter.doFilter(request, response, filterChain);
		verify(filterChain).doFilter(request, response);
		verifyNoInteractions(this.authenticationManager);
	}

	@Test
	public void doFilterWhenDeviceAuthorizationRequestThenDeviceAuthorizationResponse() throws Exception {
		Authentication authenticationResult = createAuthentication();
		given(this.authenticationManager.authenticate(any(Authentication.class))).willReturn(authenticationResult);

		Authentication clientPrincipal = (Authentication) authenticationResult.getPrincipal();
		mockSecurityContext(clientPrincipal);

		MockHttpServletRequest request = createRequest();
		request.addParameter("custom-param-1", "custom-value-1");
		request.addParameter("custom-param-2", "custom-value-1", "custom-value-2");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.filter.doFilter(request, response, filterChain);
		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());

		ArgumentCaptor<OAuth2DeviceAuthorizationRequestAuthenticationToken> deviceAuthorizationRequestAuthenticationCaptor = ArgumentCaptor
			.forClass(OAuth2DeviceAuthorizationRequestAuthenticationToken.class);
		verify(this.authenticationManager).authenticate(deviceAuthorizationRequestAuthenticationCaptor.capture());
		verifyNoInteractions(filterChain);

		OAuth2DeviceAuthorizationRequestAuthenticationToken deviceAuthorizationRequestAuthentication = deviceAuthorizationRequestAuthenticationCaptor
			.getValue();
		assertThat(deviceAuthorizationRequestAuthentication.getAuthorizationUri()).endsWith(AUTHORIZATION_URI);
		assertThat(deviceAuthorizationRequestAuthentication.getPrincipal()).isEqualTo(clientPrincipal);
		assertThat(deviceAuthorizationRequestAuthentication.getScopes()).isEmpty();
		assertThat(deviceAuthorizationRequestAuthentication.getAdditionalParameters()).containsExactly(
				Map.entry("custom-param-1", "custom-value-1"),
				Map.entry("custom-param-2", new String[] { "custom-value-1", "custom-value-2" }));
		// @formatter:off
		assertThat(deviceAuthorizationRequestAuthentication.getDetails())
				.asInstanceOf(InstanceOfAssertFactories.type(WebAuthenticationDetails.class))
				.extracting(WebAuthenticationDetails::getRemoteAddress)
				.isEqualTo(REMOTE_ADDRESS);
		// @formatter:on

		OAuth2DeviceAuthorizationResponse deviceAuthorizationResponse = readDeviceAuthorizationResponse(response);
		String verificationUri = ISSUER_URI + VERIFICATION_URI;
		assertThat(deviceAuthorizationResponse.getVerificationUri()).isEqualTo(verificationUri);
		assertThat(deviceAuthorizationResponse.getVerificationUriComplete())
			.isEqualTo("%s?%s=%s".formatted(verificationUri, OAuth2ParameterNames.USER_CODE, USER_CODE));
		OAuth2DeviceCode deviceCode = deviceAuthorizationResponse.getDeviceCode();
		assertThat(deviceCode.getTokenValue()).isEqualTo(DEVICE_CODE);
		assertThat(deviceCode.getExpiresAt()).isAfter(deviceCode.getIssuedAt());
		OAuth2UserCode userCode = deviceAuthorizationResponse.getUserCode();
		assertThat(userCode.getTokenValue()).isEqualTo(USER_CODE);
		assertThat(deviceCode.getExpiresAt()).isAfter(deviceCode.getIssuedAt());
	}

	// gh-1714
	@Test
	public void doFilterWhenDeviceAuthorizationRequestWithContextPathThenVerificationUriIncludesContextPath()
			throws Exception {
		Authentication authenticationResult = createAuthentication();
		given(this.authenticationManager.authenticate(any(Authentication.class))).willReturn(authenticationResult);

		Authentication clientPrincipal = (Authentication) authenticationResult.getPrincipal();
		mockSecurityContext(clientPrincipal);

		MockHttpServletRequest request = createRequest();
		request.setContextPath("/contextPath");
		request.setRequestURI("/contextPath" + AUTHORIZATION_URI);

		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.filter.doFilter(request, response, filterChain);
		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());

		verify(this.authenticationManager).authenticate(any(OAuth2DeviceAuthorizationRequestAuthenticationToken.class));
		verifyNoInteractions(filterChain);

		OAuth2DeviceAuthorizationResponse deviceAuthorizationResponse = readDeviceAuthorizationResponse(response);
		String verificationUri = ISSUER_URI + "/contextPath" + VERIFICATION_URI;
		assertThat(deviceAuthorizationResponse.getVerificationUri()).isEqualTo(verificationUri);
		assertThat(deviceAuthorizationResponse.getVerificationUriComplete())
			.isEqualTo("%s?%s=%s".formatted(verificationUri, OAuth2ParameterNames.USER_CODE, USER_CODE));
	}

	@Test
	public void doFilterWhenInvalidRequestErrorThenBadRequest() throws Exception {
		AuthenticationConverter authenticationConverter = mock(AuthenticationConverter.class);
		OAuth2AuthenticationException authenticationException = new OAuth2AuthenticationException(
				new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Invalid request", "error-uri"));
		given(authenticationConverter.convert(any(HttpServletRequest.class))).willThrow(authenticationException);
		this.filter.setAuthenticationConverter(authenticationConverter);

		MockHttpServletRequest request = createRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.filter.doFilter(request, response, filterChain);
		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());

		verify(authenticationConverter).convert(request);
		verifyNoInteractions(filterChain, this.authenticationManager);

		OAuth2Error error = readError(response);
		assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		assertThat(error.getDescription()).isEqualTo("Invalid request");
		assertThat(error.getUri()).isEqualTo("error-uri");
	}

	@Test
	public void doFilterWhenCustomDeviceAuthorizationEndpointUriThenUsed() throws Exception {
		Authentication authenticationResult = createAuthentication();
		given(this.authenticationManager.authenticate(any(Authentication.class))).willReturn(authenticationResult);

		Authentication clientPrincipal = (Authentication) authenticationResult.getPrincipal();
		mockSecurityContext(clientPrincipal);

		MockHttpServletRequest request = createRequest();
		request.setRequestURI("/device");
		request.setServletPath("/device");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.filter = new OAuth2DeviceAuthorizationEndpointFilter(this.authenticationManager, "/device");
		this.filter.doFilter(request, response, filterChain);
		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());

		verify(this.authenticationManager).authenticate(any(Authentication.class));
		verifyNoInteractions(filterChain);
	}

	@Test
	public void doFilterWhenAuthenticationConverterSetThenUsed() throws Exception {
		Authentication authenticationResult = createAuthentication();
		given(this.authenticationManager.authenticate(any(Authentication.class))).willReturn(authenticationResult);

		Authentication clientPrincipal = (Authentication) authenticationResult.getPrincipal();
		mockSecurityContext(clientPrincipal);

		AuthenticationConverter authenticationConverter = mock(AuthenticationConverter.class);
		OAuth2DeviceAuthorizationRequestAuthenticationToken authenticationRequest = new OAuth2DeviceAuthorizationRequestAuthenticationToken(
				clientPrincipal, AUTHORIZATION_URI, null, null);
		given(authenticationConverter.convert(any(HttpServletRequest.class))).willReturn(authenticationRequest);
		this.filter.setAuthenticationConverter(authenticationConverter);

		MockHttpServletRequest request = createRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.filter.doFilter(request, response, filterChain);
		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());

		verify(authenticationConverter).convert(request);
		verify(this.authenticationManager).authenticate(authenticationRequest);
		verifyNoInteractions(filterChain);
	}

	@Test
	public void doFilterWhenAuthenticationDetailsSourceSetThenUsed() throws Exception {
		Authentication authenticationResult = createAuthentication();
		given(this.authenticationManager.authenticate(any(Authentication.class))).willReturn(authenticationResult);

		Authentication clientPrincipal = (Authentication) authenticationResult.getPrincipal();
		mockSecurityContext(clientPrincipal);

		MockHttpServletRequest request = createRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		@SuppressWarnings("unchecked")
		AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource = mock(
				AuthenticationDetailsSource.class);
		given(authenticationDetailsSource.buildDetails(any(HttpServletRequest.class)))
			.willReturn(new WebAuthenticationDetails(request));
		this.filter.setAuthenticationDetailsSource(authenticationDetailsSource);

		this.filter.doFilter(request, response, filterChain);
		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());

		verify(this.authenticationManager).authenticate(any(Authentication.class));
		verify(authenticationDetailsSource).buildDetails(request);
		verifyNoInteractions(filterChain);
	}

	@Test
	public void doFilterWhenAuthenticationSuccessHandlerSetThenUsed() throws Exception {
		Authentication authenticationResult = createAuthentication();
		given(this.authenticationManager.authenticate(any(Authentication.class))).willReturn(authenticationResult);

		Authentication clientPrincipal = (Authentication) authenticationResult.getPrincipal();
		mockSecurityContext(clientPrincipal);

		AuthenticationSuccessHandler authenticationSuccessHandler = mock(AuthenticationSuccessHandler.class);
		this.filter.setAuthenticationSuccessHandler(authenticationSuccessHandler);

		MockHttpServletRequest request = createRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.filter.doFilter(request, response, filterChain);
		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());

		verify(this.authenticationManager).authenticate(any(Authentication.class));
		verify(authenticationSuccessHandler).onAuthenticationSuccess(request, response, authenticationResult);
		verifyNoInteractions(filterChain);
	}

	@Test
	public void doFilterWhenAuthenticationFailureHandlerSetThenUsed() throws Exception {
		OAuth2AuthenticationException authenticationException = new OAuth2AuthenticationException(
				OAuth2ErrorCodes.INVALID_REQUEST);
		given(this.authenticationManager.authenticate(any(Authentication.class))).willThrow(authenticationException);

		Authentication clientPrincipal = (Authentication) createAuthentication().getPrincipal();
		mockSecurityContext(clientPrincipal);

		AuthenticationFailureHandler authenticationFailureHandler = mock(AuthenticationFailureHandler.class);
		this.filter.setAuthenticationFailureHandler(authenticationFailureHandler);

		MockHttpServletRequest request = createRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.filter.doFilter(request, response, filterChain);
		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());

		verify(this.authenticationManager).authenticate(any(Authentication.class));
		verify(authenticationFailureHandler).onAuthenticationFailure(request, response, authenticationException);
		verifyNoInteractions(filterChain);
	}

	private OAuth2DeviceAuthorizationResponse readDeviceAuthorizationResponse(MockHttpServletResponse response)
			throws IOException {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(response.getContentAsByteArray(),
				HttpStatus.valueOf(response.getStatus()));
		return this.deviceAuthorizationHttpResponseConverter.read(OAuth2DeviceAuthorizationResponse.class,
				httpResponse);
	}

	private OAuth2Error readError(MockHttpServletResponse response) throws IOException {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(response.getContentAsByteArray(),
				HttpStatus.valueOf(response.getStatus()));
		return this.errorHttpResponseConverter.read(OAuth2Error.class, httpResponse);
	}

	private static void mockAuthorizationServerContext() {
		AuthorizationServerSettings authorizationServerSettings = AuthorizationServerSettings.builder().build();
		TestAuthorizationServerContext authorizationServerContext = new TestAuthorizationServerContext(
				authorizationServerSettings, () -> ISSUER_URI);
		AuthorizationServerContextHolder.setContext(authorizationServerContext);
	}

	private static void mockSecurityContext(Authentication clientPrincipal) {
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(clientPrincipal);
		SecurityContextHolder.setContext(securityContext);
	}

	private static MockHttpServletRequest createRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod(HttpMethod.POST.name());
		request.setRequestURI(AUTHORIZATION_URI);
		request.setServletPath(AUTHORIZATION_URI);
		request.setRemoteAddr(REMOTE_ADDRESS);
		request.setScheme("https");
		request.setServerName("provider.com");
		request.setServerPort(8090);
		return request;
	}

	private static OAuth2DeviceAuthorizationRequestAuthenticationToken createAuthentication() {
		TestingAuthenticationToken clientPrincipal = new TestingAuthenticationToken(CLIENT_ID, null);
		return new OAuth2DeviceAuthorizationRequestAuthenticationToken(clientPrincipal, null, createDeviceCode(),
				createUserCode());
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
