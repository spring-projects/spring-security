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
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceAuthorizationConsentAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceVerificationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.context.TestAuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.web.util.UriComponentsBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link OAuth2DeviceVerificationEndpointFilter}.
 *
 * @author Steve Riesenberg
 */
public class OAuth2DeviceVerificationEndpointFilterTests {

	private static final String ISSUER_URI = "https://provider.com";

	private static final String REMOTE_ADDRESS = "remote-address";

	private static final String AUTHORIZATION_URI = "/oauth2/device_authorization";

	private static final String VERIFICATION_URI = "/oauth2/device_verification";

	private static final String CLIENT_ID = "client-1";

	private static final String STATE = "12345";

	private static final String USER_CODE = "BCDF-GHJK";

	private AuthenticationManager authenticationManager;

	private OAuth2DeviceVerificationEndpointFilter filter;

	@BeforeEach
	public void setUp() {
		this.authenticationManager = mock(AuthenticationManager.class);
		this.filter = new OAuth2DeviceVerificationEndpointFilter(this.authenticationManager);
		mockAuthorizationServerContext();
	}

	@AfterEach
	public void tearDown() {
		SecurityContextHolder.clearContext();
		AuthorizationServerContextHolder.resetContext();
	}

	@Test
	public void constructorWhenAuthenticationManagerIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2DeviceVerificationEndpointFilter(null))
				.withMessage("authenticationManager cannot be null");
		// @formatter:on
	}

	@Test
	public void constructorWhenDeviceVerificationEndpointUriIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2DeviceVerificationEndpointFilter(this.authenticationManager, null))
				.withMessage("deviceVerificationEndpointUri cannot be empty");
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
	public void doFilterWhenNotDeviceVerificationRequestThenNotProcessed() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), "/path");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.filter.doFilter(request, response, filterChain);
		verify(filterChain).doFilter(request, response);
		verifyNoInteractions(this.authenticationManager);
	}

	@Test
	public void doFilterWhenUnauthenticatedThenPassThrough() throws Exception {
		TestingAuthenticationToken unauthenticatedResult = new TestingAuthenticationToken("user", null);
		given(this.authenticationManager.authenticate(any(Authentication.class))).willReturn(unauthenticatedResult);

		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.USER_CODE, USER_CODE);
		updateQueryString(request);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.filter.doFilter(request, response, filterChain);
		verify(this.authenticationManager).authenticate(any(Authentication.class));
		verify(filterChain).doFilter(request, response);
	}

	@Test
	public void doFilterWhenDeviceAuthorizationConsentRequestThenSuccess() throws Exception {
		Authentication authenticationResult = createDeviceVerificationAuthentication();
		given(this.authenticationManager.authenticate(any(Authentication.class))).willReturn(authenticationResult);

		Authentication clientPrincipal = (Authentication) authenticationResult.getPrincipal();
		mockSecurityContext(clientPrincipal);

		MockHttpServletRequest request = createRequest();
		request.setMethod(HttpMethod.POST.name());
		request.addParameter(OAuth2ParameterNames.SCOPE, "scope-1");
		request.addParameter(OAuth2ParameterNames.SCOPE, "scope-2");
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID);
		request.addParameter(OAuth2ParameterNames.STATE, STATE);
		request.addParameter(OAuth2ParameterNames.USER_CODE, USER_CODE);
		request.addParameter("custom-param-1", "custom-value-1");
		request.addParameter("custom-param-2", "custom-value-1", "custom-value-2");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.filter.doFilter(request, response, filterChain);
		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getHeader(HttpHeaders.LOCATION)).isEqualTo("/?success");

		ArgumentCaptor<OAuth2DeviceAuthorizationConsentAuthenticationToken> authenticationCaptor = ArgumentCaptor
			.forClass(OAuth2DeviceAuthorizationConsentAuthenticationToken.class);
		verify(this.authenticationManager).authenticate(authenticationCaptor.capture());
		verifyNoInteractions(filterChain);

		OAuth2DeviceAuthorizationConsentAuthenticationToken deviceAuthorizationConsentAuthentication = authenticationCaptor
			.getValue();
		assertThat(deviceAuthorizationConsentAuthentication.getAuthorizationUri()).endsWith(VERIFICATION_URI);
		assertThat(deviceAuthorizationConsentAuthentication.getClientId()).isEqualTo(CLIENT_ID);
		assertThat(deviceAuthorizationConsentAuthentication.getPrincipal())
			.isInstanceOf(TestingAuthenticationToken.class);
		assertThat(deviceAuthorizationConsentAuthentication.getUserCode()).isEqualTo(USER_CODE);
		assertThat(deviceAuthorizationConsentAuthentication.getScopes()).containsExactly("scope-1", "scope-2");
		assertThat(deviceAuthorizationConsentAuthentication.getAdditionalParameters()).containsExactly(
				Map.entry("custom-param-1", "custom-value-1"),
				Map.entry("custom-param-2", new String[] { "custom-value-1", "custom-value-2" }));
	}

	@Test
	public void doFilterWhenDeviceVerificationRequestAndConsentNotRequiredThenSuccess() throws Exception {
		Authentication authenticationResult = createDeviceVerificationAuthentication();
		given(this.authenticationManager.authenticate(any(Authentication.class))).willReturn(authenticationResult);

		Authentication clientPrincipal = (Authentication) authenticationResult.getPrincipal();
		mockSecurityContext(clientPrincipal);

		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.USER_CODE, USER_CODE);
		request.addParameter("custom-param-1", "custom-value-1");
		updateQueryString(request);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.filter.doFilter(request, response, filterChain);
		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getHeader(HttpHeaders.LOCATION)).isEqualTo("/?success");

		ArgumentCaptor<OAuth2DeviceVerificationAuthenticationToken> authenticationCaptor = ArgumentCaptor
			.forClass(OAuth2DeviceVerificationAuthenticationToken.class);
		verify(this.authenticationManager).authenticate(authenticationCaptor.capture());
		verifyNoInteractions(filterChain);

		OAuth2DeviceVerificationAuthenticationToken deviceVerificationAuthentication = authenticationCaptor.getValue();
		assertThat(deviceVerificationAuthentication.getPrincipal()).isInstanceOf(TestingAuthenticationToken.class);
		assertThat(deviceVerificationAuthentication.getUserCode()).isEqualTo(USER_CODE);
		assertThat(deviceVerificationAuthentication.getAdditionalParameters())
			.containsExactly(Map.entry("custom-param-1", "custom-value-1"));
	}

	@Test
	public void doFilterWhenDeviceVerificationRequestAndConsentRequiredThenConsentScreen() throws Exception {
		Authentication authenticationResult = createDeviceAuthorizationConsentAuthentication();
		given(this.authenticationManager.authenticate(any(Authentication.class))).willReturn(authenticationResult);

		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.USER_CODE, USER_CODE);
		updateQueryString(request);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.filter.doFilter(request, response, filterChain);
		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
		assertThat(response.getContentType())
			.isEqualTo(new MediaType("text", "html", StandardCharsets.UTF_8).toString());
		assertThat(response.getContentAsString()).contains(scopeCheckbox("scope-1"));
		assertThat(response.getContentAsString()).contains(scopeCheckbox("scope-2"));

		verify(this.authenticationManager).authenticate(any(Authentication.class));
		verifyNoInteractions(filterChain);
	}

	@Test
	public void doFilterWhenDeviceVerificationRequestAndConsentRequiredWithPreviouslyApprovedThenConsentScreen()
			throws Exception {
		Authentication authenticationResult = createDeviceAuthorizationConsentAuthenticationWithAuthorizedScopes();
		given(this.authenticationManager.authenticate(any(Authentication.class))).willReturn(authenticationResult);

		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.USER_CODE, USER_CODE);
		updateQueryString(request);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.filter.doFilter(request, response, filterChain);
		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
		assertThat(response.getContentType())
			.isEqualTo(new MediaType("text", "html", StandardCharsets.UTF_8).toString());
		assertThat(response.getContentAsString()).contains(disabledScopeCheckbox("scope-1"));
		assertThat(response.getContentAsString()).contains(scopeCheckbox("scope-2"));

		verify(this.authenticationManager).authenticate(any(Authentication.class));
		verifyNoInteractions(filterChain);
	}

	@Test
	public void doFilterWhenDeviceVerificationRequestAndConsentRequiredAndConsentPageSetThenRedirect()
			throws Exception {
		Authentication authentication = createDeviceAuthorizationConsentAuthentication();
		given(this.authenticationManager.authenticate(any(Authentication.class))).willReturn(authentication);

		MockHttpServletRequest request = createRequest();
		request.setScheme("https");
		request.setServerPort(443);
		request.setServerName("provider.com");
		request.addParameter(OAuth2ParameterNames.USER_CODE, USER_CODE);
		updateQueryString(request);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.filter.setConsentPage("/consent");
		this.filter.doFilter(request, response, filterChain);
		String redirectUri = UriComponentsBuilder.fromUriString("https://provider.com/consent")
			.queryParam(OAuth2ParameterNames.SCOPE, "scope-1 scope-2")
			.queryParam(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID)
			.queryParam(OAuth2ParameterNames.STATE, STATE)
			.queryParam(OAuth2ParameterNames.USER_CODE, USER_CODE)
			.toUriString();
		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getHeader(HttpHeaders.LOCATION)).isEqualTo(redirectUri);

		verify(this.authenticationManager).authenticate(any(Authentication.class));
		verifyNoInteractions(filterChain);
	}

	@Test
	public void doFilterWhenAuthenticationConverterSetThenUsed() throws Exception {
		Authentication authenticationResult = createDeviceVerificationAuthentication();
		given(this.authenticationManager.authenticate(any(Authentication.class))).willReturn(authenticationResult);

		AuthenticationConverter authenticationConverter = mock(AuthenticationConverter.class);
		OAuth2DeviceVerificationAuthenticationToken deviceVerificationAuthentication = new OAuth2DeviceVerificationAuthenticationToken(
				(Authentication) authenticationResult.getPrincipal(), USER_CODE, Collections.emptyMap());
		given(authenticationConverter.convert(any(HttpServletRequest.class)))
			.willReturn(deviceVerificationAuthentication);
		this.filter.setAuthenticationConverter(authenticationConverter);

		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.USER_CODE, USER_CODE);
		updateQueryString(request);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.filter.doFilter(request, response, filterChain);
		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getHeader(HttpHeaders.LOCATION)).isEqualTo("/?success");

		verify(authenticationConverter).convert(request);
		verify(this.authenticationManager).authenticate(any(Authentication.class));
		verifyNoInteractions(filterChain);
	}

	@Test
	public void doFilterWhenAuthenticationDetailsSourceSetThenUsed() throws Exception {
		Authentication authenticationResult = createDeviceVerificationAuthentication();
		given(this.authenticationManager.authenticate(any(Authentication.class))).willReturn(authenticationResult);

		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.USER_CODE, USER_CODE);
		updateQueryString(request);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		@SuppressWarnings("unchecked")
		AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource = mock(
				AuthenticationDetailsSource.class);
		given(authenticationDetailsSource.buildDetails(any(HttpServletRequest.class)))
			.willReturn(new WebAuthenticationDetails(request));
		this.filter.setAuthenticationDetailsSource(authenticationDetailsSource);

		this.filter.doFilter(request, response, filterChain);
		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getHeader(HttpHeaders.LOCATION)).isEqualTo("/?success");

		verify(this.authenticationManager).authenticate(any(Authentication.class));
		verify(authenticationDetailsSource).buildDetails(request);
		verifyNoInteractions(filterChain);
	}

	@Test
	public void doFilterWhenAuthenticationSuccessHandlerSetThenUsed() throws Exception {
		Authentication authenticationResult = createDeviceVerificationAuthentication();
		given(this.authenticationManager.authenticate(any(Authentication.class))).willReturn(authenticationResult);

		AuthenticationSuccessHandler authenticationSuccessHandler = mock(AuthenticationSuccessHandler.class);
		this.filter.setAuthenticationSuccessHandler(authenticationSuccessHandler);

		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.USER_CODE, USER_CODE);
		updateQueryString(request);
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

		AuthenticationFailureHandler authenticationFailureHandler = mock(AuthenticationFailureHandler.class);
		this.filter.setAuthenticationFailureHandler(authenticationFailureHandler);

		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.USER_CODE, USER_CODE);
		updateQueryString(request);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.filter.doFilter(request, response, filterChain);
		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());

		verify(this.authenticationManager).authenticate(any(Authentication.class));
		verify(authenticationFailureHandler).onAuthenticationFailure(request, response, authenticationException);
		verifyNoInteractions(filterChain);
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

	private static OAuth2DeviceVerificationAuthenticationToken createDeviceVerificationAuthentication() {
		TestingAuthenticationToken principal = new TestingAuthenticationToken("user", null);
		return new OAuth2DeviceVerificationAuthenticationToken(principal, CLIENT_ID, USER_CODE);
	}

	private static Authentication createDeviceAuthorizationConsentAuthentication() {
		TestingAuthenticationToken principal = new TestingAuthenticationToken("user", null);
		Set<String> requestedScopes = new HashSet<>();
		requestedScopes.add("scope-1");
		requestedScopes.add("scope-2");
		return new OAuth2DeviceAuthorizationConsentAuthenticationToken(AUTHORIZATION_URI, CLIENT_ID, principal,
				USER_CODE, STATE, requestedScopes, new HashSet<>());
	}

	private static Authentication createDeviceAuthorizationConsentAuthenticationWithAuthorizedScopes() {
		TestingAuthenticationToken principal = new TestingAuthenticationToken("user", null);
		Set<String> requestedScopes = new HashSet<>();
		requestedScopes.add("scope-1");
		requestedScopes.add("scope-2");
		Set<String> authorizedScopes = new HashSet<>();
		authorizedScopes.add("scope-1");
		return new OAuth2DeviceAuthorizationConsentAuthenticationToken(AUTHORIZATION_URI, CLIENT_ID, principal,
				USER_CODE, STATE, requestedScopes, authorizedScopes);
	}

	private static MockHttpServletRequest createRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod(HttpMethod.GET.name());
		request.setRequestURI(VERIFICATION_URI);
		request.setServletPath(VERIFICATION_URI);
		request.setRemoteAddr(REMOTE_ADDRESS);
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
