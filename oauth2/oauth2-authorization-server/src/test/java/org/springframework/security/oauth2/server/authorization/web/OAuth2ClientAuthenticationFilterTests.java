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

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link OAuth2ClientAuthenticationFilter}.
 *
 * @author Patryk Kostrzewa
 * @author Joe Grandja
 */
public class OAuth2ClientAuthenticationFilterTests {

	private String filterProcessesUrl = "/oauth2/token";

	private AuthenticationManager authenticationManager;

	private RequestMatcher requestMatcher;

	private AuthenticationConverter authenticationConverter;

	private OAuth2ClientAuthenticationFilter filter;

	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter = new OAuth2ErrorHttpMessageConverter();

	@BeforeEach
	public void setUp() {
		this.authenticationManager = mock(AuthenticationManager.class);
		this.requestMatcher = PathPatternRequestMatcher.withDefaults()
			.matcher(HttpMethod.POST, this.filterProcessesUrl);
		this.filter = new OAuth2ClientAuthenticationFilter(this.authenticationManager, this.requestMatcher);
		this.authenticationConverter = mock(AuthenticationConverter.class);
		this.filter.setAuthenticationConverter(this.authenticationConverter);
	}

	@AfterEach
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void constructorWhenAuthenticationManagerNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> new OAuth2ClientAuthenticationFilter(null, this.requestMatcher))
			.withMessage("authenticationManager cannot be null");
	}

	@Test
	public void constructorWhenRequestMatcherNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> new OAuth2ClientAuthenticationFilter(this.authenticationManager, null))
			.withMessage("requestMatcher cannot be null");
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
	public void doFilterWhenRequestDoesNotMatchThenNotProcessed() throws Exception {
		String requestUri = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		verifyNoInteractions(this.authenticationConverter);
	}

	@Test
	public void doFilterWhenRequestMatchesAndEmptyCredentialsThenNotProcessed() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", this.filterProcessesUrl);
		request.setServletPath(this.filterProcessesUrl);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		verifyNoInteractions(this.authenticationManager);
	}

	@Test
	public void doFilterWhenRequestMatchesAndInvalidCredentialsThenInvalidRequestError() throws Exception {
		given(this.authenticationConverter.convert(any(HttpServletRequest.class)))
			.willThrow(new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST));

		MockHttpServletRequest request = new MockHttpServletRequest("POST", this.filterProcessesUrl);
		request.setServletPath(this.filterProcessesUrl);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		OAuth2Error error = readError(response);
		assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
	}

	// gh-889
	@Test
	public void doFilterWhenRequestMatchesAndClientIdContainsNonPrintableASCIIThenInvalidRequestError()
			throws Exception {
		// Hex 00 -> null
		String clientId = new String(Hex.decode("00"), StandardCharsets.UTF_8);
		assertWhenInvalidClientIdThenInvalidRequestError(clientId);

		// Hex 0a61 -> line feed + a
		clientId = new String(Hex.decode("0a61"), StandardCharsets.UTF_8);
		assertWhenInvalidClientIdThenInvalidRequestError(clientId);

		// Hex 1b -> escape
		clientId = new String(Hex.decode("1b"), StandardCharsets.UTF_8);
		assertWhenInvalidClientIdThenInvalidRequestError(clientId);

		// Hex 1b61 -> escape + a
		clientId = new String(Hex.decode("1b61"), StandardCharsets.UTF_8);
		assertWhenInvalidClientIdThenInvalidRequestError(clientId);
	}

	private void assertWhenInvalidClientIdThenInvalidRequestError(String clientId) throws Exception {
		given(this.authenticationConverter.convert(any(HttpServletRequest.class)))
			.willReturn(new OAuth2ClientAuthenticationToken(clientId, ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
					"secret", null));

		MockHttpServletRequest request = new MockHttpServletRequest("POST", this.filterProcessesUrl);
		request.setServletPath(this.filterProcessesUrl);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);
		verifyNoInteractions(this.authenticationManager);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		OAuth2Error error = readError(response);
		assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
	}

	@Test
	public void doFilterWhenRequestMatchesAndBadCredentialsThenInvalidClientError() throws Exception {
		given(this.authenticationConverter.convert(any(HttpServletRequest.class)))
			.willReturn(new OAuth2ClientAuthenticationToken("clientId", ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
					"invalid-secret", null));
		given(this.authenticationManager.authenticate(any(Authentication.class)))
			.willThrow(new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT));

		MockHttpServletRequest request = new MockHttpServletRequest("POST", this.filterProcessesUrl);
		request.setServletPath(this.filterProcessesUrl);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);
		verify(this.authenticationManager).authenticate(any());

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
		OAuth2Error error = readError(response);
		assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void doFilterWhenRequestMatchesAndValidCredentialsThenProcessed() throws Exception {
		final String remoteAddress = "remote-address";

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		given(this.authenticationConverter.convert(any(HttpServletRequest.class)))
			.willReturn(new OAuth2ClientAuthenticationToken(registeredClient.getClientId(),
					ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret(), null));
		given(this.authenticationManager.authenticate(any(Authentication.class)))
			.willReturn(new OAuth2ClientAuthenticationToken(registeredClient,
					ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret()));

		MockHttpServletRequest request = new MockHttpServletRequest("POST", this.filterProcessesUrl);
		request.setServletPath(this.filterProcessesUrl);
		request.setRemoteAddr(remoteAddress);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		assertThat(authentication).isInstanceOf(OAuth2ClientAuthenticationToken.class);
		assertThat(((OAuth2ClientAuthenticationToken) authentication).getRegisteredClient())
			.isEqualTo(registeredClient);

		ArgumentCaptor<OAuth2ClientAuthenticationToken> authenticationRequestCaptor = ArgumentCaptor
			.forClass(OAuth2ClientAuthenticationToken.class);
		verify(this.authenticationManager).authenticate(authenticationRequestCaptor.capture());
		assertThat(authenticationRequestCaptor).extracting(ArgumentCaptor::getValue)
			.extracting(OAuth2ClientAuthenticationToken::getDetails)
			.asInstanceOf(InstanceOfAssertFactories.type(WebAuthenticationDetails.class))
			.extracting(WebAuthenticationDetails::getRemoteAddress)
			.isEqualTo(remoteAddress);
	}

	private OAuth2Error readError(MockHttpServletResponse response) throws Exception {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(response.getContentAsByteArray(),
				HttpStatus.valueOf(response.getStatus()));
		return this.errorHttpResponseConverter.read(OAuth2Error.class, httpResponse);
	}

}
