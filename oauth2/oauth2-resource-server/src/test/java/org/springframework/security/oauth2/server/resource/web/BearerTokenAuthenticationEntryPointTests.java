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

package org.springframework.security.oauth2.server.resource.web;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrorCodes;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link BearerTokenAuthenticationEntryPoint}.
 *
 * @author Vedran Pavic
 * @author Josh Cummings
 */
public class BearerTokenAuthenticationEntryPointTests {

	private BearerTokenAuthenticationEntryPoint authenticationEntryPoint;

	@BeforeEach
	public void setUp() {
		this.authenticationEntryPoint = new BearerTokenAuthenticationEntryPoint();
	}

	@Test
	public void commenceWhenNoBearerTokenErrorThenStatus401AndAuthHeader() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.authenticationEntryPoint.commence(request, response, new BadCredentialsException("test"));
		assertThat(response.getStatus()).isEqualTo(401);
		assertThat(response.getHeader("WWW-Authenticate"))
			.isEqualTo("Bearer resource_metadata=\"http://localhost/.well-known/oauth-protected-resource\"");
	}

	@Test
	public void commenceWhenNoBearerTokenErrorAndRealmSetThenStatus401AndAuthHeaderWithRealm() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.authenticationEntryPoint.setRealmName("test");
		this.authenticationEntryPoint.commence(request, response, new BadCredentialsException("test"));
		assertThat(response.getStatus()).isEqualTo(401);
		assertThat(response.getHeader("WWW-Authenticate")).isEqualTo(
				"Bearer realm=\"test\", resource_metadata=\"http://localhost/.well-known/oauth-protected-resource\"");
	}

	@Test
	public void commenceWhenNoBearerTokenErrorAndContextPathSetThenStatus401AndAuthHeaderWithContextPath() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setContextPath("/ctx");
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.authenticationEntryPoint.commence(request, response, new BadCredentialsException("test"));
		assertThat(response.getStatus()).isEqualTo(401);
		assertThat(response.getHeader("WWW-Authenticate"))
			.isEqualTo("Bearer resource_metadata=\"http://localhost/ctx/.well-known/oauth-protected-resource\"");

	}

	@Test
	public void commenceWhenNoBearerTokenErrorAndResourceMetadataResolverSetThenStatus401AndAuthHeaderWithResolvedResourceMetadata() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setAttribute("resource_id", "https://example.com/resource-from-request");
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.authenticationEntryPoint
			.setResourceMetadataParameterResolver((req) -> req.getAttribute("resource_id").toString());
		this.authenticationEntryPoint.commence(request, response, new BadCredentialsException("test"));
		assertThat(response.getStatus()).isEqualTo(401);
		assertThat(response.getHeader("WWW-Authenticate"))
			.isEqualTo("Bearer resource_metadata=\"https://example.com/resource-from-request\"");
	}

	@Test
	public void commenceWhenInvalidRequestErrorThenStatus400AndHeaderWithError() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		BearerTokenError error = new BearerTokenError(BearerTokenErrorCodes.INVALID_REQUEST, HttpStatus.BAD_REQUEST,
				null, null);
		this.authenticationEntryPoint.commence(request, response, new OAuth2AuthenticationException(error));
		assertThat(response.getStatus()).isEqualTo(400);
		assertThat(response.getHeader("WWW-Authenticate")).isEqualTo(
				"Bearer error=\"invalid_request\", resource_metadata=\"http://localhost/.well-known/oauth-protected-resource\"");
	}

	@Test
	public void commenceWhenInvalidRequestErrorThenStatus400AndHeaderWithErrorDetails() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		BearerTokenError error = new BearerTokenError(BearerTokenErrorCodes.INVALID_REQUEST, HttpStatus.BAD_REQUEST,
				"The access token expired", null, null);
		this.authenticationEntryPoint.commence(request, response, new OAuth2AuthenticationException(error));
		assertThat(response.getStatus()).isEqualTo(400);
		assertThat(response.getHeader("WWW-Authenticate")).isEqualTo(
				"Bearer error=\"invalid_request\", error_description=\"The access token expired\", resource_metadata=\"http://localhost/.well-known/oauth-protected-resource\"");
	}

	@Test
	public void commenceWhenInvalidRequestErrorThenStatus400AndHeaderWithErrorUri() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		BearerTokenError error = new BearerTokenError(BearerTokenErrorCodes.INVALID_REQUEST, HttpStatus.BAD_REQUEST,
				null, "https://example.com", null);
		this.authenticationEntryPoint.commence(request, response, new OAuth2AuthenticationException(error));
		assertThat(response.getStatus()).isEqualTo(400);
		assertThat(response.getHeader("WWW-Authenticate")).isEqualTo(
				"Bearer error=\"invalid_request\", error_uri=\"https://example.com\", resource_metadata=\"http://localhost/.well-known/oauth-protected-resource\"");
	}

	@Test
	public void commenceWhenInvalidTokenErrorThenStatus401AndHeaderWithError() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		BearerTokenError error = new BearerTokenError(BearerTokenErrorCodes.INVALID_TOKEN, HttpStatus.UNAUTHORIZED,
				null, null);
		this.authenticationEntryPoint.commence(request, response, new OAuth2AuthenticationException(error));
		assertThat(response.getStatus()).isEqualTo(401);
		assertThat(response.getHeader("WWW-Authenticate")).isEqualTo(
				"Bearer error=\"invalid_token\", resource_metadata=\"http://localhost/.well-known/oauth-protected-resource\"");
	}

	@Test
	public void commenceWhenInsufficientScopeErrorThenStatus403AndHeaderWithError() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		BearerTokenError error = new BearerTokenError(BearerTokenErrorCodes.INSUFFICIENT_SCOPE, HttpStatus.FORBIDDEN,
				null, null);
		this.authenticationEntryPoint.commence(request, response, new OAuth2AuthenticationException(error));
		assertThat(response.getStatus()).isEqualTo(403);
		assertThat(response.getHeader("WWW-Authenticate")).isEqualTo(
				"Bearer error=\"insufficient_scope\", resource_metadata=\"http://localhost/.well-known/oauth-protected-resource\"");
	}

	@Test
	public void commenceWhenInsufficientScopeErrorThenStatus403AndHeaderWithErrorAndScope() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		BearerTokenError error = new BearerTokenError(BearerTokenErrorCodes.INSUFFICIENT_SCOPE, HttpStatus.FORBIDDEN,
				null, null, "test.read test.write");
		this.authenticationEntryPoint.commence(request, response, new OAuth2AuthenticationException(error));
		assertThat(response.getStatus()).isEqualTo(403);
		assertThat(response.getHeader("WWW-Authenticate")).isEqualTo(
				"Bearer error=\"insufficient_scope\", scope=\"test.read test.write\", resource_metadata=\"http://localhost/.well-known/oauth-protected-resource\"");
	}

	@Test
	public void commenceWhenInsufficientScopeAndRealmSetThenStatus403AndHeaderWithErrorAndAllDetails()
			throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		BearerTokenError error = new BearerTokenError(BearerTokenErrorCodes.INSUFFICIENT_SCOPE, HttpStatus.FORBIDDEN,
				"Insufficient scope", "https://example.com", "test.read test.write");
		this.authenticationEntryPoint.setRealmName("test");
		this.authenticationEntryPoint.commence(request, response, new OAuth2AuthenticationException(error));
		assertThat(response.getStatus()).isEqualTo(403);
		assertThat(response.getHeader("WWW-Authenticate"))
			.isEqualTo("Bearer realm=\"test\", error=\"insufficient_scope\", error_description=\"Insufficient scope\", "
					+ "error_uri=\"https://example.com\", scope=\"test.read test.write\", resource_metadata=\"http://localhost/.well-known/oauth-protected-resource\"");
	}

	@Test
	public void setRealmNameWhenNullRealmNameThenNoExceptionThrown() {
		this.authenticationEntryPoint.setRealmName(null);
	}

}
