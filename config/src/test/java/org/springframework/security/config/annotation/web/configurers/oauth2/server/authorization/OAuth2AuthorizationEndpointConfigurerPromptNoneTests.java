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

package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.OidcPromptNoneExceptionHandlingFilter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.mock;

/**
 * Tests for OIDC {@code prompt=none} handling in
 * {@link OAuth2AuthorizationEndpointConfigurer}.
 *
 * @author suuuuuuminnnnnn
 */
public class OAuth2AuthorizationEndpointConfigurerPromptNoneTests {

	private static final String CLIENT_ID = "test-client";

	private static final String REDIRECT_URI = "https://example.com/callback";

	private static final String STATE = "test-state";

	private OidcPromptNoneExceptionHandlingFilter filter;

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private FilterChain filterChain;

	private AuthenticationConverter authenticationConverter;

	@BeforeEach
	public void setup() {
		this.authenticationConverter = mock(AuthenticationConverter.class);

		this.filter = new OidcPromptNoneExceptionHandlingFilter(AnyRequestMatcher.INSTANCE,
				this.authenticationConverter, new OAuth2AuthorizationCodeRequestAuthenticationFailureHandler());

		this.request = new MockHttpServletRequest();
		this.request.setMethod("GET");
		this.request.setRequestURI("/oauth2/authorize");
		this.request.setServletPath("/oauth2/authorize");

		this.response = new MockHttpServletResponse();

		this.filterChain = mock(FilterChain.class);
	}

	@Test
	public void doFilterWhenPromptNoneAndAccessDeniedThenLoginRequiredError() throws Exception {
		// Setup request with prompt=none
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put("prompt", "none");

		OAuth2AuthorizationCodeRequestAuthenticationToken authRequest = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				"http://localhost/oauth2/authorize", CLIENT_ID,
				new AnonymousAuthenticationToken("key", "anonymousUser",
						AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")),
				REDIRECT_URI, STATE, new HashSet<>(Arrays.asList("openid")), additionalParameters);

		given(this.authenticationConverter.convert(any())).willReturn(authRequest);

		// Mock filter chain to throw AccessDeniedException
		willThrow(new AccessDeniedException("Access Denied")).given(this.filterChain).doFilter(any(), any());

		// Execute filter
		this.filter.doFilter(this.request, this.response, this.filterChain);

		// Verify redirect to client with error
		assertThat(this.response.getStatus()).isEqualTo(302);
		String location = this.response.getHeader("Location");
		assertThat(location).isNotNull();
		assertThat(location).startsWith(REDIRECT_URI);
		assertThat(location).contains("error=login_required");
		assertThat(location).contains("state=" + STATE);
		assertThat(location).doesNotContain("code=");
	}

	@Test
	public void doFilterWhenPromptNoneWithMultipleValuesAndAccessDeniedThenLoginRequiredError() throws Exception {
		// Setup request with prompt containing 'none' among other values
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put("prompt", "consent none");

		OAuth2AuthorizationCodeRequestAuthenticationToken authRequest = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				"http://localhost/oauth2/authorize", CLIENT_ID,
				new AnonymousAuthenticationToken("key", "anonymousUser",
						AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")),
				REDIRECT_URI, STATE, new HashSet<>(Arrays.asList("openid")), additionalParameters);

		given(this.authenticationConverter.convert(any())).willReturn(authRequest);

		// Mock filter chain to throw AccessDeniedException
		willThrow(new AccessDeniedException("Access Denied")).given(this.filterChain).doFilter(any(), any());

		// Execute filter
		this.filter.doFilter(this.request, this.response, this.filterChain);

		// Verify redirect to client with error
		assertThat(this.response.getStatus()).isEqualTo(302);
		String location = this.response.getHeader("Location");
		assertThat(location).isNotNull();
		assertThat(location).contains("error=login_required");
	}

	@Test
	public void doFilterWhenNoPromptNoneAndAccessDeniedThenExceptionThrown() throws Exception {
		// Setup request WITHOUT prompt=none
		OAuth2AuthorizationCodeRequestAuthenticationToken authRequest = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				"http://localhost/oauth2/authorize", CLIENT_ID,
				new AnonymousAuthenticationToken("key", "anonymousUser",
						AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")),
				REDIRECT_URI, STATE, new HashSet<>(Arrays.asList("openid")), new HashMap<>());

		given(this.authenticationConverter.convert(any())).willReturn(authRequest);

		// Mock filter chain to throw AccessDeniedException
		AccessDeniedException expectedException = new AccessDeniedException("Access Denied");
		willThrow(expectedException).given(this.filterChain).doFilter(any(), any());

		// Execute filter and expect exception to be re-thrown
		try {
			this.filter.doFilter(this.request, this.response, this.filterChain);
			throw new AssertionError("Expected AccessDeniedException to be thrown");
		}
		catch (AccessDeniedException ex) {
			assertThat(ex).isSameAs(expectedException);
		}
	}

	@Test
	public void doFilterWhenPromptNoneWithoutOpenidScopeAndAccessDeniedThenExceptionThrown() throws Exception {
		// Setup request with prompt=none but WITHOUT openid scope
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put("prompt", "none");

		OAuth2AuthorizationCodeRequestAuthenticationToken authRequest = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				"http://localhost/oauth2/authorize", CLIENT_ID,
				new AnonymousAuthenticationToken("key", "anonymousUser",
						AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")),
				REDIRECT_URI, STATE, new HashSet<>(Arrays.asList("profile", "email")), additionalParameters);

		given(this.authenticationConverter.convert(any())).willReturn(authRequest);

		// Mock filter chain to throw AccessDeniedException
		AccessDeniedException expectedException = new AccessDeniedException("Access Denied");
		willThrow(expectedException).given(this.filterChain).doFilter(any(), any());

		// Execute filter and expect exception to be re-thrown
		try {
			this.filter.doFilter(this.request, this.response, this.filterChain);
			throw new AssertionError("Expected AccessDeniedException to be thrown");
		}
		catch (AccessDeniedException ex) {
			assertThat(ex).isSameAs(expectedException);
		}
	}

	@Test
	public void doFilterWhenPromptNoneAndNoExceptionThenContinuesNormally() throws Exception {
		// Setup request with prompt=none
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put("prompt", "none");

		OAuth2AuthorizationCodeRequestAuthenticationToken authRequest = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				"http://localhost/oauth2/authorize", CLIENT_ID,
				new AnonymousAuthenticationToken("key", "anonymousUser",
						AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")),
				REDIRECT_URI, STATE, new HashSet<>(Arrays.asList("openid")), additionalParameters);

		given(this.authenticationConverter.convert(any())).willReturn(authRequest);

		// Execute filter without exception
		this.filter.doFilter(this.request, this.response, this.filterChain);

		// Verify no error response
		assertThat(this.response.getStatus()).isEqualTo(200);
	}

}
