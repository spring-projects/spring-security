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

import java.time.Instant;
import java.util.Collections;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JoseHeaderNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link OidcUserInfoEndpointFilter}.
 *
 * @author Steve Riesenberg
 */
public class OidcUserInfoEndpointFilterTests {

	private static final String DEFAULT_OIDC_USER_INFO_ENDPOINT_URI = "/userinfo";

	private AuthenticationManager authenticationManager;

	private OidcUserInfoEndpointFilter filter;

	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter = new OAuth2ErrorHttpMessageConverter();

	@BeforeEach
	public void setup() {
		this.authenticationManager = mock(AuthenticationManager.class);
		this.filter = new OidcUserInfoEndpointFilter(this.authenticationManager, DEFAULT_OIDC_USER_INFO_ENDPOINT_URI);
	}

	@Test
	public void constructorWhenAuthenticationManagerNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new OidcUserInfoEndpointFilter(null))
			.withMessage("authenticationManager cannot be null");
	}

	@Test
	public void constructorWhenUserInfoEndpointUriIsEmptyThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new OidcUserInfoEndpointFilter(this.authenticationManager, ""))
			.withMessage("userInfoEndpointUri cannot be empty");
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
	public void doFilterWhenNotUserInfoRequestThenNotProcessed() throws Exception {
		String requestUri = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(request, response);
	}

	@Test
	public void doFilterWhenUserInfoRequestPutThenNotProcessed() throws Exception {
		String requestUri = DEFAULT_OIDC_USER_INFO_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("PUT", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(this.authenticationManager);
		verify(filterChain).doFilter(request, response);
	}

	@Test
	public void doFilterWhenUserInfoRequestGetThenSuccess() throws Exception {
		doFilterWhenUserInfoRequestThenSuccess("GET");
	}

	@Test
	public void doFilterWhenUserInfoRequestPostThenSuccess() throws Exception {
		doFilterWhenUserInfoRequestThenSuccess("POST");
	}

	private void doFilterWhenUserInfoRequestThenSuccess(String httpMethod) throws Exception {
		JwtAuthenticationToken principal = createJwtAuthenticationToken();
		SecurityContextHolder.getContext().setAuthentication(principal);

		OidcUserInfoAuthenticationToken authentication = new OidcUserInfoAuthenticationToken(principal,
				createUserInfo());
		given(this.authenticationManager.authenticate(any())).willReturn(authentication);

		String requestUri = DEFAULT_OIDC_USER_INFO_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest(httpMethod, requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);

		assertThat(response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
		assertUserInfoResponse(response.getContentAsString());
	}

	@Test
	public void doFilterWhenUserInfoRequestInvalidTokenThenUnauthorizedError() throws Exception {
		doFilterWhenAuthenticationExceptionThenError(OAuth2ErrorCodes.INVALID_TOKEN, HttpStatus.UNAUTHORIZED);
	}

	@Test
	public void doFilterWhenUserInfoRequestInsufficientScopeThenForbiddenError() throws Exception {
		doFilterWhenAuthenticationExceptionThenError(OAuth2ErrorCodes.INSUFFICIENT_SCOPE, HttpStatus.FORBIDDEN);
	}

	private void doFilterWhenAuthenticationExceptionThenError(String oauth2ErrorCode, HttpStatus httpStatus)
			throws Exception {
		Authentication principal = new TestingAuthenticationToken("principal", "credentials");
		SecurityContextHolder.getContext().setAuthentication(principal);

		given(this.authenticationManager.authenticate(any()))
			.willThrow(new OAuth2AuthenticationException(oauth2ErrorCode));

		String requestUri = DEFAULT_OIDC_USER_INFO_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(httpStatus.value());
		OAuth2Error error = readError(response);
		assertThat(error.getErrorCode()).isEqualTo(oauth2ErrorCode);
	}

	@Test
	public void doFilterWhenCustomAuthenticationConverterThenUsed() throws Exception {
		Authentication principal = new TestingAuthenticationToken("principal", "credentials");
		OidcUserInfoAuthenticationToken authentication = new OidcUserInfoAuthenticationToken(principal);
		AuthenticationConverter authenticationConverter = mock(AuthenticationConverter.class);
		this.filter.setAuthenticationConverter(authenticationConverter);

		given(authenticationConverter.convert(any())).willReturn(authentication);
		given(this.authenticationManager.authenticate(any()))
			.willReturn(new OidcUserInfoAuthenticationToken(principal, createUserInfo()));

		String requestUri = DEFAULT_OIDC_USER_INFO_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);
		verify(authenticationConverter).convert(request);
		verify(this.authenticationManager).authenticate(authentication);
		assertUserInfoResponse(response.getContentAsString());
	}

	@Test
	public void doFilterWhenCustomAuthenticationSuccessHandlerThenUsed() throws Exception {
		AuthenticationSuccessHandler successHandler = mock(AuthenticationSuccessHandler.class);
		this.filter.setAuthenticationSuccessHandler(successHandler);

		Authentication principal = new TestingAuthenticationToken("principal", "credentials");
		SecurityContextHolder.getContext().setAuthentication(principal);

		OidcUserInfoAuthenticationToken authentication = new OidcUserInfoAuthenticationToken(principal,
				createUserInfo());
		given(this.authenticationManager.authenticate(any())).willReturn(authentication);

		String requestUri = DEFAULT_OIDC_USER_INFO_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);
		verify(successHandler).onAuthenticationSuccess(request, response, authentication);
	}

	@Test
	public void doFilterWhenCustomAuthenticationFailureHandlerThenUsed() throws Exception {
		AuthenticationFailureHandler failureHandler = mock(AuthenticationFailureHandler.class);
		this.filter.setAuthenticationFailureHandler(failureHandler);

		Authentication principal = new TestingAuthenticationToken("principal", "credentials");
		SecurityContextHolder.getContext().setAuthentication(principal);

		OAuth2AuthenticationException authenticationException = new OAuth2AuthenticationException(
				OAuth2ErrorCodes.INVALID_TOKEN);
		given(this.authenticationManager.authenticate(any())).willThrow(authenticationException);

		String requestUri = DEFAULT_OIDC_USER_INFO_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);
		verify(failureHandler).onAuthenticationFailure(request, response, authenticationException);
	}

	private OAuth2Error readError(MockHttpServletResponse response) throws Exception {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(response.getContentAsByteArray(),
				HttpStatus.valueOf(response.getStatus()));
		return this.errorHttpResponseConverter.read(OAuth2Error.class, httpResponse);
	}

	private JwtAuthenticationToken createJwtAuthenticationToken() {
		Instant now = Instant.now();
		// @formatter:off
		Jwt jwt = Jwt.withTokenValue("token")
				.header(JoseHeaderNames.ALG, SignatureAlgorithm.RS256.getName())
				.issuedAt(now)
				.expiresAt(now.plusSeconds(300))
				.claim(StandardClaimNames.SUB, "user")
				.build();
		// @formatter:on
		return new JwtAuthenticationToken(jwt, Collections.emptyList());
	}

	private static OidcUserInfo createUserInfo() {
		return OidcUserInfo.builder()
			.subject("user1")
			.name("First Last")
			.givenName("First")
			.familyName("Last")
			.middleName("Middle")
			.nickname("User")
			.preferredUsername("user")
			.profile("https://example.com/user1")
			.picture("https://example.com/user1.jpg")
			.website("https://example.com")
			.email("user1@example.com")
			.emailVerified(true)
			.gender("female")
			.birthdate("1970-01-01")
			.zoneinfo("Europe/Paris")
			.locale("en-US")
			.phoneNumber("+1 (604) 555-1234;ext=5678")
			.phoneNumberVerified(false)
			.address("Champ de Mars\n5 Av. Anatole France\n75007 Paris\nFrance")
			.updatedAt("1970-01-01T00:00:00Z")
			.build();
	}

	private static void assertUserInfoResponse(String userInfoResponse) {
		assertThat(userInfoResponse).contains("\"sub\":\"user1\"");
		assertThat(userInfoResponse).contains("\"name\":\"First Last\"");
		assertThat(userInfoResponse).contains("\"given_name\":\"First\"");
		assertThat(userInfoResponse).contains("\"family_name\":\"Last\"");
		assertThat(userInfoResponse).contains("\"middle_name\":\"Middle\"");
		assertThat(userInfoResponse).contains("\"nickname\":\"User\"");
		assertThat(userInfoResponse).contains("\"preferred_username\":\"user\"");
		assertThat(userInfoResponse).contains("\"profile\":\"https://example.com/user1\"");
		assertThat(userInfoResponse).contains("\"picture\":\"https://example.com/user1.jpg\"");
		assertThat(userInfoResponse).contains("\"website\":\"https://example.com\"");
		assertThat(userInfoResponse).contains("\"email\":\"user1@example.com\"");
		assertThat(userInfoResponse).contains("\"email_verified\":true");
		assertThat(userInfoResponse).contains("\"gender\":\"female\"");
		assertThat(userInfoResponse).contains("\"birthdate\":\"1970-01-01\"");
		assertThat(userInfoResponse).contains("\"zoneinfo\":\"Europe/Paris\"");
		assertThat(userInfoResponse).contains("\"locale\":\"en-US\"");
		assertThat(userInfoResponse).contains("\"phone_number\":\"+1 (604) 555-1234;ext=5678\"");
		assertThat(userInfoResponse).contains("\"phone_number_verified\":false");
		assertThat(userInfoResponse)
			.contains("\"address\":\"Champ de Mars\\n5 Av. Anatole France\\n75007 Paris\\nFrance\"");
		assertThat(userInfoResponse).contains("\"updated_at\":\"1970-01-01T00:00:00Z\"");
	}

}
