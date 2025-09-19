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

import java.io.IOException;
import java.time.Instant;
import java.util.Collections;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.TestJwsHeaders;
import org.springframework.security.oauth2.jwt.TestJwtClaimsSets;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.http.converter.OAuth2ClientRegistrationHttpMessageConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link OAuth2ClientRegistrationEndpointFilter}.
 *
 * @author Joe Grandja
 */
public class OAuth2ClientRegistrationEndpointFilterTests {

	private static final String DEFAULT_OAUTH2_CLIENT_REGISTRATION_ENDPOINT_URI = "/oauth2/register";

	private AuthenticationManager authenticationManager;

	private OAuth2ClientRegistrationEndpointFilter filter;

	private final HttpMessageConverter<OAuth2ClientRegistration> clientRegistrationHttpMessageConverter = new OAuth2ClientRegistrationHttpMessageConverter();

	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter = new OAuth2ErrorHttpMessageConverter();

	@BeforeEach
	public void setup() {
		this.authenticationManager = mock(AuthenticationManager.class);
		this.filter = new OAuth2ClientRegistrationEndpointFilter(this.authenticationManager);
	}

	@AfterEach
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void constructorWhenAuthenticationManagerNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new OAuth2ClientRegistrationEndpointFilter(null))
			.withMessage("authenticationManager cannot be null");
	}

	@Test
	public void constructorWhenClientRegistrationEndpointUriNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new OAuth2ClientRegistrationEndpointFilter(this.authenticationManager, null))
			.withMessage("clientRegistrationEndpointUri cannot be empty");
	}

	@Test
	public void setAuthenticationConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setAuthenticationConverter(null))
			.withMessage("authenticationConverter cannot be null");
	}

	@Test
	public void setAuthenticationSuccessHandlerWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setAuthenticationSuccessHandler(null))
			.withMessage("authenticationSuccessHandler cannot be null");
	}

	@Test
	public void setAuthenticationFailureHandlerWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setAuthenticationFailureHandler(null))
			.withMessage("authenticationFailureHandler cannot be null");
	}

	@Test
	public void doFilterWhenNotClientRegistrationRequestThenNotProcessed() throws Exception {
		String requestUri = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenClientRegistrationRequestGetThenNotProcessed() throws Exception {
		String requestUri = DEFAULT_OAUTH2_CLIENT_REGISTRATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenClientRegistrationRequestInvalidThenInvalidRequestError() throws Exception {
		String requestUri = DEFAULT_OAUTH2_CLIENT_REGISTRATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		request.setContent("invalid content".getBytes());
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		OAuth2Error error = readError(response);
		assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		assertThat(error.getDescription()).startsWith("OAuth 2.0 Client Registration Error: ");
	}

	@Test
	public void doFilterWhenClientRegistrationRequestInvalidTokenThenUnauthorizedError() throws Exception {
		doFilterWhenClientRegistrationRequestInvalidThenError(OAuth2ErrorCodes.INVALID_TOKEN, HttpStatus.UNAUTHORIZED);
	}

	@Test
	public void doFilterWhenClientRegistrationRequestInsufficientTokenScopeThenForbiddenError() throws Exception {
		doFilterWhenClientRegistrationRequestInvalidThenError(OAuth2ErrorCodes.INSUFFICIENT_SCOPE,
				HttpStatus.FORBIDDEN);
	}

	private void doFilterWhenClientRegistrationRequestInvalidThenError(String errorCode, HttpStatus status)
			throws Exception {
		Jwt jwt = createJwt("client.create");
		JwtAuthenticationToken principal = new JwtAuthenticationToken(jwt,
				AuthorityUtils.createAuthorityList("SCOPE_client.create"));

		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(principal);
		SecurityContextHolder.setContext(securityContext);

		given(this.authenticationManager.authenticate(any())).willThrow(new OAuth2AuthenticationException(errorCode));

		// @formatter:off
		OAuth2ClientRegistration clientRegistrationRequest = OAuth2ClientRegistration.builder()
				.clientName("client-name")
				.redirectUri("https://client.example.com")
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.scope("scope1")
				.scope("scope2")
				.build();
		// @formatter:on

		String requestUri = DEFAULT_OAUTH2_CLIENT_REGISTRATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		writeClientRegistrationRequest(request, clientRegistrationRequest);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(status.value());
		OAuth2Error error = readError(response);
		assertThat(error.getErrorCode()).isEqualTo(errorCode);
	}

	@Test
	public void doFilterWhenClientRegistrationRequestValidThenSuccessResponse() throws Exception {
		// @formatter:off
		OAuth2ClientRegistration expectedClientRegistrationResponse = createClientRegistration();

		OAuth2ClientRegistration clientRegistrationRequest = OAuth2ClientRegistration.builder()
				.clientName(expectedClientRegistrationResponse.getClientName())
				.redirectUris((redirectUris) -> redirectUris.addAll(expectedClientRegistrationResponse.getRedirectUris()))
				.grantTypes((grantTypes) -> grantTypes.addAll(expectedClientRegistrationResponse.getGrantTypes()))
				.scopes((scopes) -> scopes.addAll(expectedClientRegistrationResponse.getScopes()))
				.build();
		// @formatter:on

		Jwt jwt = createJwt("client.create");
		JwtAuthenticationToken principal = new JwtAuthenticationToken(jwt,
				AuthorityUtils.createAuthorityList("SCOPE_client.create"));

		OAuth2ClientRegistrationAuthenticationToken clientRegistrationAuthenticationResult = new OAuth2ClientRegistrationAuthenticationToken(
				principal, expectedClientRegistrationResponse);

		given(this.authenticationManager.authenticate(any())).willReturn(clientRegistrationAuthenticationResult);

		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(principal);
		SecurityContextHolder.setContext(securityContext);

		String requestUri = DEFAULT_OAUTH2_CLIENT_REGISTRATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		writeClientRegistrationRequest(request, clientRegistrationRequest);

		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.CREATED.value());
		OAuth2ClientRegistration clientRegistrationResponse = readClientRegistrationResponse(response);
		assertThat(clientRegistrationResponse.getClientId())
			.isEqualTo(expectedClientRegistrationResponse.getClientId());
		assertThat(clientRegistrationResponse.getClientIdIssuedAt()).isBetween(
				expectedClientRegistrationResponse.getClientIdIssuedAt().minusSeconds(1),
				expectedClientRegistrationResponse.getClientIdIssuedAt().plusSeconds(1));
		assertThat(clientRegistrationResponse.getClientSecret())
			.isEqualTo(expectedClientRegistrationResponse.getClientSecret());
		assertThat(clientRegistrationResponse.getClientSecretExpiresAt())
			.isEqualTo(expectedClientRegistrationResponse.getClientSecretExpiresAt());
		assertThat(clientRegistrationResponse.getClientName())
			.isEqualTo(expectedClientRegistrationResponse.getClientName());
		assertThat(clientRegistrationResponse.getRedirectUris())
			.containsExactlyInAnyOrderElementsOf(expectedClientRegistrationResponse.getRedirectUris());
		assertThat(clientRegistrationResponse.getGrantTypes())
			.containsExactlyInAnyOrderElementsOf(expectedClientRegistrationResponse.getGrantTypes());
		assertThat(clientRegistrationResponse.getResponseTypes())
			.containsExactlyInAnyOrderElementsOf(expectedClientRegistrationResponse.getResponseTypes());
		assertThat(clientRegistrationResponse.getScopes())
			.containsExactlyInAnyOrderElementsOf(expectedClientRegistrationResponse.getScopes());
		assertThat(clientRegistrationResponse.getTokenEndpointAuthenticationMethod())
			.isEqualTo(expectedClientRegistrationResponse.getTokenEndpointAuthenticationMethod());
	}

	@Test
	public void doFilterWhenCustomAuthenticationConverterThenUsed() throws ServletException, IOException {
		AuthenticationConverter authenticationConverter = mock(AuthenticationConverter.class);
		this.filter.setAuthenticationConverter(authenticationConverter);

		String requestUri = DEFAULT_OAUTH2_CLIENT_REGISTRATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(authenticationConverter).convert(request);
	}

	@Test
	public void doFilterWhenCustomAuthenticationSuccessHandlerThenUsed() throws Exception {
		OAuth2ClientRegistration expectedClientRegistrationResponse = createClientRegistration();
		Authentication principal = new TestingAuthenticationToken("principal", "Credentials");

		OAuth2ClientRegistrationAuthenticationToken clientRegistrationAuthenticationResult = new OAuth2ClientRegistrationAuthenticationToken(
				principal, expectedClientRegistrationResponse);

		given(this.authenticationManager.authenticate(any())).willReturn(clientRegistrationAuthenticationResult);
		AuthenticationSuccessHandler successHandler = mock(AuthenticationSuccessHandler.class);
		this.filter.setAuthenticationSuccessHandler(successHandler);

		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(principal);
		SecurityContextHolder.setContext(securityContext);

		// @formatter:off
		OAuth2ClientRegistration clientRegistrationRequest = OAuth2ClientRegistration.builder()
				.clientName("client-name")
				.redirectUri("https://client.example.com")
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.scope("scope1")
				.scope("scope2")
				.build();
		// @formatter:on

		String requestUri = DEFAULT_OAUTH2_CLIENT_REGISTRATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		writeClientRegistrationRequest(request, clientRegistrationRequest);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(successHandler).onAuthenticationSuccess(request, response, clientRegistrationAuthenticationResult);
	}

	@Test
	public void doFilterWhenCustomAuthenticationFailureHandlerThenUsed() throws Exception {
		AuthenticationFailureHandler authenticationFailureHandler = mock(AuthenticationFailureHandler.class);
		this.filter.setAuthenticationFailureHandler(authenticationFailureHandler);

		String requestUri = DEFAULT_OAUTH2_CLIENT_REGISTRATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		request.setContent("invalid content".getBytes());
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(authenticationFailureHandler).onAuthenticationFailure(eq(request), eq(response),
				any(OAuth2AuthenticationException.class));
	}

	private OAuth2Error readError(MockHttpServletResponse response) throws Exception {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(response.getContentAsByteArray(),
				HttpStatus.valueOf(response.getStatus()));
		return this.errorHttpResponseConverter.read(OAuth2Error.class, httpResponse);
	}

	private void writeClientRegistrationRequest(MockHttpServletRequest request,
			OAuth2ClientRegistration clientRegistration) throws Exception {
		MockClientHttpRequest httpRequest = new MockClientHttpRequest();
		this.clientRegistrationHttpMessageConverter.write(clientRegistration, null, httpRequest);
		request.setContent(httpRequest.getBodyAsBytes());
	}

	private OAuth2ClientRegistration readClientRegistrationResponse(MockHttpServletResponse response) throws Exception {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(response.getContentAsByteArray(),
				HttpStatus.valueOf(response.getStatus()));
		return this.clientRegistrationHttpMessageConverter.read(OAuth2ClientRegistration.class, httpResponse);
	}

	private static OAuth2ClientRegistration createClientRegistration() {
		// @formatter:off
		return OAuth2ClientRegistration.builder()
				.clientId("client-id")
				.clientIdIssuedAt(Instant.now())
				.clientSecret("client-secret")
				.clientName("client-name")
				.redirectUri("https://client.example.com")
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.tokenEndpointAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue())
				.responseType(OAuth2AuthorizationResponseType.CODE.getValue())
				.scope("scope1")
				.scope("scope2")
				.build();
		// @formatter:on
	}

	private static Jwt createJwt(String scope) {
		// @formatter:off
		JwsHeader jwsHeader = TestJwsHeaders.jwsHeader()
				.build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet()
				.claim(OAuth2ParameterNames.SCOPE, Collections.singleton(scope))
				.build();
		Jwt jwt = Jwt.withTokenValue("jwt-access-token")
				.headers((headers) -> headers.putAll(jwsHeader.getHeaders()))
				.claims((claims) -> claims.putAll(jwtClaimsSet.getClaims()))
				.build();
		// @formatter:on
		return jwt;
	}

}
